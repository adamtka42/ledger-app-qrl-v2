#include "typed_data.h"

#include <stdio.h>
#include <string.h>

#include "address_format.h"
#include "keccak256.h"

static void hash_bytes(const uint8_t *bytes, size_t length, uint8_t digest[32]) {
    keccak256_ctx hash;
    keccak256_init(&hash);
    keccak256_absorb(&hash, bytes, length);
    keccak256_finalize(&hash);
    keccak256_squeeze(&hash, digest);
    keccak256_clear(&hash);
}

static const uint8_t *take(typed_data_t *data, size_t length) {
    if (data->cursor > data->received_len || length > data->received_len - data->cursor)
        return NULL;
    const uint8_t *bytes = data->payload + data->cursor;
    data->cursor += length;
    return bytes;
}

static bool byte(typed_data_t *data, uint8_t *out) {
    const uint8_t *p = take(data, 1);
    if (p == NULL) return false;
    *out = *p;
    return true;
}

bool typed_data_name(const typed_data_t *data, typed_span_t name, char *out, size_t size) {
    if (data == NULL || out == NULL || size <= name.length || name.offset > data->received_len ||
        name.length > data->received_len - name.offset)
        return false;
    memcpy(out, data->payload + name.offset, name.length);
    out[name.length] = '\0';
    return true;
}

static bool equal(const typed_data_t *data, typed_span_t span, const char *text) {
    return span.length == strlen(text) &&
           memcmp(data->payload + span.offset, text, span.length) == 0;
}

static int compare(const typed_data_t *data, typed_span_t a, typed_span_t b) {
    size_t length = a.length < b.length ? a.length : b.length;
    int order = memcmp(data->payload + a.offset, data->payload + b.offset, length);
    return order != 0 ? order : (int) a.length - (int) b.length;
}

typedef enum { NAME_FIELD, NAME_TYPE, NAME_TYPE_REFERENCE } name_kind_t;

static bool identifier(const uint8_t *name, size_t length, bool type_name) {
    if (length == 0 || length > TYPED_DATA_MAX_NAME) return false;
    /* go-qrl reference types must start with an ASCII letter. Field names may
     * still start with '_'; applying the same rule to them would reject valid data. */
    if (type_name && !((name[0] >= 'A' && name[0] <= 'Z') || (name[0] >= 'a' && name[0] <= 'z')))
        return false;
    for (size_t i = 0; i < length; i++) {
        uint8_t c = name[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' ||
              (i != 0 && c >= '0' && c <= '9')))
            return false;
    }
    return true;
}

static bool read_name(typed_data_t *data, typed_span_t *out, name_kind_t kind) {
    uint8_t length;
    if (!byte(data, &length)) return false;
    out->offset = (uint16_t) data->cursor;
    out->length = length;
    const uint8_t *p = take(data, length);
    if (p == NULL) return false;
    size_t base = length;
    if (kind == NAME_TYPE_REFERENCE && base >= 2 && p[base - 2] == '[' && p[base - 1] == ']')
        base -= 2;
    return identifier(p, base, kind != NAME_FIELD);
}

/* QRVM words are 64 bytes: integers have at most 512 bits, fixed bytes at most 64. */
enum { MAX_INT_BITS = 512, MAX_FIXED_BYTES = 64 };

/* The N of uintN, intN or bytesN, in canonical decimal. A bare uint or int means
 * the full word; a bare "bytes" never reaches here. */
static bool parse_width(const char *number, typed_kind_t kind, uint16_t *width) {
    if (*number == '\0') {
        if (kind == TYPED_FIXED_BYTES) return false;
        *width = MAX_INT_BITS;
        return true;
    }
    if (*number == '0') return false;
    unsigned value = 0;
    for (; *number != '\0'; number++) {
        if (*number < '0' || *number > '9' || value > MAX_INT_BITS) return false;
        value = value * 10 + (unsigned) (*number - '0');
    }
    if (kind == TYPED_FIXED_BYTES) {
        if (value == 0 || value > MAX_FIXED_BYTES) return false;
    } else if (value == 0 || value > MAX_INT_BITS || value % 8 != 0) {
        return false;
    }
    *width = (uint16_t) value;
    return true;
}

static bool classify_primitive(typed_field_t *field, const char *type) {
    /* Inline arrays avoid unrelocated pointers in the Ledger PIC address space. */
    static const struct {
        char name[8];
        typed_kind_t kind;
    } exact[] = {
        {"address", TYPED_ADDRESS},
        {"bool", TYPED_BOOL},
        {"string", TYPED_STRING},
        {"bytes", TYPED_BYTES},
    };
    static const struct {
        char prefix[6];
        typed_kind_t kind;
    } sized[] = {
        {"uint", TYPED_UINT},
        {"int", TYPED_INT},
        {"bytes", TYPED_FIXED_BYTES},
    };
    for (size_t i = 0; i < sizeof(exact) / sizeof(exact[0]); i++) {
        if (strcmp(type, exact[i].name) == 0) {
            field->kind = exact[i].kind;
            return true;
        }
    }
    for (size_t i = 0; i < sizeof(sized) / sizeof(sized[0]); i++) {
        const size_t prefix = strlen(sized[i].prefix);
        if (strncmp(type, sized[i].prefix, prefix) == 0) {
            field->kind = sized[i].kind;
            return parse_width(type + prefix, field->kind, &field->width);
        }
    }
    return false;
}

static bool find_struct(const typed_data_t *data, const char *type, uint8_t *index) {
    for (uint8_t i = 0; i < data->type_count; i++) {
        if (equal(data, data->types[i].name, type)) {
            *index = i;
            return true;
        }
    }
    return false;
}

/* Resolve a field's type name, with an optional [] suffix, to a struct defined in
 * this payload or to a primitive. */
static bool classify(typed_data_t *data, typed_field_t *field, bool references) {
    char type[TYPED_DATA_MAX_NAME + 3];
    if (!typed_data_name(data, field->type_name, type, sizeof(type))) return false;
    const size_t length = strlen(type);
    field->array = length >= 2 && strcmp(type + length - 2, "[]") == 0;
    if (field->array) type[length - 2] = '\0';
    if (references && find_struct(data, type, &field->reference)) {
        field->kind = TYPED_STRUCT;
        return true;
    }
    return classify_primitive(field, type);
}

static bool dependencies(const typed_data_t *data,
                         uint8_t type,
                         uint8_t *found,
                         uint8_t *active,
                         size_t depth) {
    uint8_t bit = (uint8_t) (1u << type);
    if (depth > TYPED_DATA_MAX_DEPTH || (*active & bit)) return false;
    /* A shared type may be reached again by a deeper path. Deduplicate the
     * resulting type list, not traversal of the depth/cycle checks. */
    *active |= bit;
    const typed_type_t *definition = &data->types[type];
    for (size_t i = 0; i < definition->field_count; i++) {
        const typed_field_t *field = &data->fields[definition->first_field + i];
        if (field->kind == TYPED_STRUCT &&
            !dependencies(data, field->reference, found, active, depth + 1))
            return false;
    }
    *active &= (uint8_t) ~bit;
    *found |= bit;
    return true;
}

static void absorb_span(keccak256_ctx *hash, const typed_data_t *data, typed_span_t span) {
    keccak256_absorb(hash, data->payload + span.offset, span.length);
}

static bool type_hash(typed_data_t *data, uint8_t type) {
    uint8_t found = 0, active = 0, order[TYPED_DATA_MAX_TYPES], count = 0;
    if (!dependencies(data, type, &found, &active, 1)) return false;
    order[count++] = type;
    for (uint8_t i = 0; i < data->type_count; i++) {
        if (i == type || !(found & (1u << i))) continue;
        size_t pos = count;
        while (pos > 1 &&
               compare(data, data->types[i].name, data->types[order[pos - 1]].name) < 0) {
            order[pos] = order[pos - 1];
            pos--;
        }
        order[pos] = i;
        count++;
    }
    keccak256_ctx hash;
    keccak256_init(&hash);
    for (size_t i = 0; i < count; i++) {
        typed_type_t *definition = &data->types[order[i]];
        absorb_span(&hash, data, definition->name);
        keccak256_absorb(&hash, (const uint8_t *) "(", 1);
        for (size_t j = 0; j < definition->field_count; j++) {
            typed_field_t *field = &data->fields[definition->first_field + j];
            if (j != 0) keccak256_absorb(&hash, (const uint8_t *) ",", 1);
            absorb_span(&hash, data, field->type_name);
            keccak256_absorb(&hash, (const uint8_t *) " ", 1);
            absorb_span(&hash, data, field->name);
        }
        keccak256_absorb(&hash, (const uint8_t *) ")", 1);
    }
    keccak256_finalize(&hash);
    keccak256_squeeze(&hash, data->types[type].hash);
    keccak256_clear(&hash);
    return true;
}

/* Version, number of types and index of the primary type. */
static bool read_schema_header(typed_data_t *data) {
    uint8_t version;
    return byte(data, &version) && version == 1 && byte(data, &data->type_count) &&
           data->type_count >= 2 && data->type_count <= TYPED_DATA_MAX_TYPES &&
           byte(data, &data->primary_type) && data->primary_type < data->type_count;
}

/* Type i: a name no earlier type has, then its fields, each named once. */
static bool read_type(typed_data_t *data, uint8_t i) {
    typed_type_t *type = &data->types[i];
    if (!read_name(data, &type->name, NAME_TYPE) || !byte(data, &type->field_count) ||
        type->field_count > TYPED_DATA_MAX_FIELDS - data->field_count)
        return false;
    for (uint8_t j = 0; j < i; j++) {
        if (compare(data, type->name, data->types[j].name) == 0) return false;
    }
    if (equal(data, type->name, "QRLTypedDataDomain")) data->domain_type = i;
    type->first_field = data->field_count;
    for (uint8_t j = 0; j < type->field_count; j++) {
        typed_field_t *field = &data->fields[data->field_count++];
        if (!read_name(data, &field->name, NAME_FIELD) ||
            !read_name(data, &field->type_name, NAME_TYPE_REFERENCE))
            return false;
        for (size_t k = 0; k < j; k++) {
            if (compare(data, field->name, data->fields[type->first_field + k].name) == 0)
                return false;
        }
    }
    return true;
}

/* Every field type is a defined struct or a primitive, and no struct is named
 * like a primitive. */
static bool resolve_types(typed_data_t *data) {
    for (size_t i = 0; i < data->type_count; i++) {
        typed_field_t candidate = {.type_name = data->types[i].name};
        if (classify(data, &candidate, false)) return false;
    }
    for (size_t i = 0; i < data->field_count; i++) {
        if (!classify(data, &data->fields[i], true)) return false;
    }
    return true;
}

/* Domain.Map in go-qrl supports exactly these names and their standard types, in
 * this order, each at most once. */
enum { DOMAIN_NAME, DOMAIN_VERSION, DOMAIN_CHAIN_ID, DOMAIN_VERIFYING_CONTRACT, DOMAIN_SALT };

static int domain_field(const typed_data_t *data, const typed_field_t *field) {
    /* Inline arrays avoid unrelocated pointers in the Ledger PIC address space. */
    static const char names[][18] = {"name", "version", "chainId", "verifyingContract", "salt"};
    static const char types[][8] = {"string", "string", "uint256", "address", "bytes32"};
    for (size_t j = 0; j < sizeof(names) / sizeof(names[0]); j++) {
        if (equal(data, field->name, names[j]) && equal(data, field->type_name, types[j]))
            return (int) j;
    }
    return -1;
}

static bool check_domain_fields(typed_data_t *data) {
    const typed_type_t *domain = &data->types[data->domain_type];
    int previous = -1;
    for (size_t i = 0; i < domain->field_count; i++) {
        const int match = domain_field(data, &data->fields[domain->first_field + i]);
        if (match <= previous) return false;
        previous = match;
        data->has_chain_id |= match == DOMAIN_CHAIN_ID;
        data->has_verifying_contract |= match == DOMAIN_VERIFYING_CONTRACT;
    }
    return true;
}

static bool schema(typed_data_t *data) {
    if (!read_schema_header(data)) return false;
    data->domain_type = UINT8_MAX;
    for (uint8_t i = 0; i < data->type_count; i++) {
        if (!read_type(data, i)) return false;
    }
    if (data->domain_type == UINT8_MAX || data->domain_type == data->primary_type ||
        data->types[data->domain_type].field_count == 0)
        return false;
    if (!resolve_types(data) || !check_domain_fields(data)) return false;
    for (uint8_t i = 0; i < data->type_count; i++) {
        if (!type_hash(data, i)) return false;
    }
    return true;
}

static bool store(typed_data_t *data, const char *text, size_t length, uint16_t *offset) {
    if (length + 1 > sizeof(data->review) - data->review_used) return false;
    *offset = (uint16_t) data->review_used;
    memcpy(data->review + data->review_used, text, length);
    data->review_used += length;
    data->review[data->review_used++] = '\0';
    return true;
}

static bool review_parts(typed_data_t *data, const char *label, char *text, size_t length) {
    uint16_t lengths[TYPED_DATA_MAX_PAIRS];
    size_t count = 0, pos = 0;
    do {
        if (count + data->pair_count >= TYPED_DATA_MAX_PAIRS) return false;
        size_t part = length - pos;
        if (data->review_page_length != NULL && part != 0) {
            part = data->review_page_length(label, text + pos);
            if (part == 0 || part > length - pos) return false;
        }
        lengths[count++] = (uint16_t) part;
        pos += part;
    } while (pos < length);
    pos = 0;
    for (size_t i = 0; i < count; i++) {
        typed_review_pair_t *pair = &data->pairs[data->pair_count++];
        char title[48];
        if (count == 1)
            snprintf(title, sizeof(title), "%s", label);
        else
            snprintf(title, sizeof(title), "%s (%u/%u)", label, (unsigned) i + 1, (unsigned) count);
        if (!store(data, title, strlen(title), &pair->label) ||
            !store(data, text + pos, lengths[i], &pair->value))
            return false;
        pos += lengths[i];
    }
    return true;
}

void typed_data_review_reset(typed_data_t *data) {
    memset(data->review, 0, sizeof(data->review));
    memset(data->pairs, 0, sizeof(data->pairs));
    data->review_used = 0;
    data->pair_count = 0;
}

bool typed_data_review_add(typed_data_t *data, const char *label, char *text) {
    return data != NULL && label != NULL && text != NULL &&
           review_parts(data, label, text, strlen(text));
}

bool typed_data_review_blob(typed_data_t *data,
                            const uint8_t *bytes,
                            size_t length,
                            uint16_t *offset) {
    return data != NULL && bytes != NULL && offset != NULL &&
           store(data, (const char *) bytes, length, offset);
}

static void hex(const uint8_t *bytes, size_t length, char *out) {
    static const char digits[] = "0123456789abcdef";
    out[0] = '0';
    out[1] = 'x';
    for (size_t i = 0; i < length; i++) {
        out[2 + 2 * i] = digits[bytes[i] >> 4];
        out[3 + 2 * i] = digits[bytes[i] & 15];
    }
    out[2 + 2 * length] = '\0';
}

static void decimal(const uint8_t word[TYPED_DATA_WORD_LEN], bool negative, char *out) {
    uint8_t value[TYPED_DATA_WORD_LEN];
    memcpy(value, word, TYPED_DATA_WORD_LEN);
    if (negative) {
        unsigned carry = 1;
        for (size_t i = TYPED_DATA_WORD_LEN; i-- > 0;) {
            unsigned digit = (unsigned) (value[i] ^ 0xff) + carry;
            value[i] = (uint8_t) digit;
            carry = digit >> 8;
        }
    }
    char reverse[155]; /* 2^512 has 155 decimal digits */
    size_t count = 0;
    bool remaining;
    do {
        unsigned remainder = 0;
        remaining = false;
        for (size_t i = 0; i < TYPED_DATA_WORD_LEN; i++) {
            unsigned digit = remainder * 256 + value[i];
            value[i] = (uint8_t) (digit / 10);
            remainder = digit % 10;
            remaining |= value[i] != 0;
        }
        reverse[count++] = (char) ('0' + remainder);
    } while (remaining);
    size_t pos = 0;
    if (negative) out[pos++] = '-';
    while (count) out[pos++] = reverse[--count];
    out[pos] = '\0';
}

/* The pair that introduces a reviewed value: "<kind> <n>" and
 * "<path>\n<type><detail>". Kept out of the recursive hashing frames. */
__attribute__((noinline)) static bool add_header(typed_data_t *data,
                                                 const char *kind,
                                                 const typed_field_t *field,
                                                 const char *path,
                                                 bool element,
                                                 const char *detail) {
    if (data->value_count == UINT8_MAX) return false;
    const unsigned number = ++data->value_count;
    char type[TYPED_DATA_MAX_NAME + 3], description[TYPED_DATA_MAX_PATH + 64], label[20];
    if (!typed_data_name(data, field->type_name, type, sizeof(type))) return false;
    if (element && field->array) type[strlen(type) - 2] = '\0';
    snprintf(description, sizeof(description), "%s\n%s%s", path, type, detail);
    snprintf(label, sizeof(label), "%s %u", kind, number);
    return review_parts(data, label, description, strlen(description));
}

static bool add_field(typed_data_t *data,
                      const typed_field_t *field,
                      const char *path,
                      char *value,
                      size_t value_length,
                      size_t raw_length) {
    char detail[24] = "";
    if (field->kind == TYPED_STRING || field->kind == TYPED_BYTES)
        snprintf(detail, sizeof(detail), ", %u bytes", (unsigned) raw_length);
    if (!add_header(data, "Field", field, path, true, detail)) return false;
    const char *leaf_name = strrchr(path, '.');
    return review_parts(data, leaf_name != NULL ? leaf_name + 1 : path, value, value_length);
}

/* Paths of empty strings that the domain may not contain. */
#define DOMAIN_PREFIX "domain."

static bool struct_hash(typed_data_t *data,
                        uint8_t type,
                        char path[TYPED_DATA_MAX_PATH],
                        size_t depth,
                        uint8_t digest[32]);

static bool value_word(typed_data_t *data,
                       const typed_field_t *field,
                       char path[TYPED_DATA_MAX_PATH],
                       size_t depth,
                       uint8_t word[TYPED_DATA_WORD_LEN]) {
    if (depth > TYPED_DATA_MAX_DEPTH) return false;
    memset(word, 0, TYPED_DATA_WORD_LEN);
    if (field->kind == TYPED_STRUCT) {
        if (!add_header(data, "Struct", field, path, true, "")) return false;
        return struct_hash(data, field->reference, path, depth + 1, word);
    }
    size_t length = field->kind == TYPED_BOOL          ? 1
                    : field->kind == TYPED_FIXED_BYTES ? field->width
                                                       : TYPED_DATA_WORD_LEN;
    if (field->kind == TYPED_STRING || field->kind == TYPED_BYTES) {
        const uint8_t *size = take(data, 2);
        if (size == NULL) return false;
        length = ((size_t) size[0] << 8) | size[1];
        if (length > TYPED_DATA_MAX_VALUE) return false;
    }
    const uint8_t *bytes = take(data, length);
    if (bytes == NULL) return false;
    data->value_offset[field - data->fields] = (uint16_t) (bytes - data->payload);
    char display[2 * TYPED_DATA_MAX_VALUE + 3];
    if (field->kind == TYPED_STRING) {
        size_t lines = 0;
        for (size_t i = 0; i < length; i++) {
            if (bytes[i] == '\n')
                lines++;
            else if (bytes[i] < 0x20 || bytes[i] > 0x7e)
                return false;
        }
        if (lines > TYPED_DATA_MAX_NEWLINES ||
            (length == 0 && strncmp(path, DOMAIN_PREFIX, sizeof(DOMAIN_PREFIX) - 1) == 0))
            return false;
        hash_bytes(bytes, length, word);
        if (length == 0)
            strcpy(display, "<empty string>");
        else {
            memcpy(display, bytes, length);
            display[length] = '\0';
        }
    } else if (field->kind == TYPED_BYTES) {
        hash_bytes(bytes, length, word);
        hex(bytes, length, display);
    } else if (field->kind == TYPED_ADDRESS) {
        memcpy(word, bytes, TYPED_DATA_WORD_LEN);
        if (!format_checksummed_address(bytes, display, sizeof(display))) return false;
    } else if (field->kind == TYPED_BOOL) {
        if (*bytes > 1) return false;
        word[TYPED_DATA_WORD_LEN - 1] = *bytes;
        strcpy(display, *bytes ? "true" : "false");
    } else if (field->kind == TYPED_FIXED_BYTES) {
        memcpy(word, bytes, length);
        hex(bytes, length, display);
    } else {
        bool negative = field->kind == TYPED_INT && (bytes[0] & 0x80);
        size_t width = field->width / 8;
        for (size_t i = 0; i < TYPED_DATA_WORD_LEN - width; i++) {
            if (bytes[i] != (negative ? 0xff : 0)) return false;
        }
        if (field->kind == TYPED_INT && !!(bytes[TYPED_DATA_WORD_LEN - width] & 0x80) != negative)
            return false;
        memcpy(word, bytes, TYPED_DATA_WORD_LEN);
        decimal(bytes, negative, display);
    }
    return add_field(data, field, path, display, strlen(display), length);
}

static bool append_path(char path[TYPED_DATA_MAX_PATH], const char *name, bool index) {
    size_t length = strlen(path), extra = strlen(name);
    if (length + extra + (index ? 0 : 1) >= TYPED_DATA_MAX_PATH) return false;
    if (!index) path[length++] = '.';
    memcpy(path + length, name, extra + 1);
    return true;
}

/* An array value: its header, then the hash of its elements' words. Kept out of
 * the struct_hash frame, which every nesting level repeats. */
__attribute__((noinline)) static bool array_word(typed_data_t *data,
                                                 const typed_field_t *field,
                                                 char path[TYPED_DATA_MAX_PATH],
                                                 size_t depth,
                                                 uint8_t word[TYPED_DATA_WORD_LEN]) {
    uint8_t count;
    if (!byte(data, &count) || count > TYPED_DATA_MAX_ARRAY) return false;
    /* Show the array's type and length even when it has no elements. */
    char detail[24];
    snprintf(detail, sizeof(detail), ", %u items", (unsigned) count);
    if (!add_header(data, "Array", field, path, false, detail)) return false;
    const size_t array_path_length = strlen(path);
    keccak256_ctx array_hash;
    keccak256_init(&array_hash);
    bool valid = true;
    for (size_t j = 0; valid && j < count; j++) {
        char index[8];
        snprintf(index, sizeof(index), "[%u]", (unsigned) j);
        path[array_path_length] = '\0';
        valid = append_path(path, index, true) && value_word(data, field, path, depth, word);
        if (valid) keccak256_absorb(&array_hash, word, TYPED_DATA_WORD_LEN);
    }
    memset(word, 0, TYPED_DATA_WORD_LEN);
    if (valid) {
        keccak256_finalize(&array_hash);
        keccak256_squeeze(&array_hash, word);
    }
    keccak256_clear(&array_hash);
    return valid;
}

static bool struct_hash(typed_data_t *data,
                        uint8_t type,
                        char path[TYPED_DATA_MAX_PATH],
                        size_t depth,
                        uint8_t digest[32]) {
    if (depth > TYPED_DATA_MAX_DEPTH) return false;
    const typed_type_t *definition = &data->types[type];
    keccak256_ctx hash;
    uint8_t word[TYPED_DATA_WORD_LEN] = {0};
    memcpy(word, definition->hash, 32);
    keccak256_init(&hash);
    keccak256_absorb(&hash, word, TYPED_DATA_WORD_LEN);
    size_t path_length = strlen(path);
    bool valid = true;
    for (size_t i = 0; valid && i < definition->field_count; i++) {
        const typed_field_t *field = &data->fields[definition->first_field + i];
        char name[TYPED_DATA_MAX_NAME + 1];
        path[path_length] = '\0';
        valid = typed_data_name(data, field->name, name, sizeof(name)) &&
                append_path(path, name, false);
        if (!valid) break;
        if (field->array)
            valid = array_word(data, field, path, depth, word);
        else
            valid = value_word(data, field, path, depth, word);
        if (valid) keccak256_absorb(&hash, word, TYPED_DATA_WORD_LEN);
    }
    path[path_length] = '\0';
    if (valid) {
        keccak256_finalize(&hash);
        keccak256_squeeze(&hash, digest);
    }
    keccak256_clear(&hash);
    return valid;
}

bool typed_data_init(typed_data_t *data, uint32_t length) {
    if (data == NULL) return false;
    memset(data, 0, sizeof(*data));
    if (length < TYPED_DATA_HEADER_LEN || length > TYPED_DATA_MAX_PAYLOAD) return false;
    data->expected_len = length;
    return true;
}

bool typed_data_feed(typed_data_t *data, const uint8_t *bytes, size_t length) {
    if (data == NULL || data->finished || data->expected_len > TYPED_DATA_MAX_PAYLOAD ||
        data->received_len > data->expected_len ||
        length > data->expected_len - data->received_len || (bytes == NULL && length != 0))
        return false;
    if (length) memcpy(data->payload + data->received_len, bytes, length);
    data->received_len += length;
    return true;
}

bool typed_data_finish(typed_data_t *data, typed_data_page_length_t page_length) {
    if (data == NULL || data->finished || data->expected_len < TYPED_DATA_HEADER_LEN ||
        data->expected_len > TYPED_DATA_MAX_PAYLOAD || data->received_len != data->expected_len)
        return false;
    data->cursor = 0;
    data->review_page_length = page_length;
    if (!schema(data)) return false;
    /* 0x19 0x01, the domain separator and the message hash. */
    enum {
        PREIMAGE_DOMAIN = 2,
        PREIMAGE_MESSAGE = PREIMAGE_DOMAIN + 32,
        PREIMAGE_LEN = PREIMAGE_MESSAGE + 32
    };
    uint8_t preimage[PREIMAGE_LEN] = {0x19, 0x01};
    char path[TYPED_DATA_MAX_PATH] = "domain";
    if (!struct_hash(data, data->domain_type, path, 1, preimage + PREIMAGE_DOMAIN)) return false;
    strcpy(path, "message");
    if (!struct_hash(data, data->primary_type, path, 1, preimage + PREIMAGE_MESSAGE) ||
        data->cursor != data->received_len)
        return false;
    hash_bytes(preimage, sizeof(preimage), data->digest);
    data->finished = true;
    return true;
}
