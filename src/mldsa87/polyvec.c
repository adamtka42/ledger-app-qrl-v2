#include "polyvec.h"
#include "poly.h"
#include "error.h"
#include <string.h>
#include "cx.h"

void poly_vec_l_uniform_gamma1(PolyVecL *v, uint8_t seed[CRH_BYTES], uint16_t nonce) {
    for (int i = (uint16_t) 0; i < L; i++) {
        poly_uniform_gamma1(&v->vec[i], seed, L * nonce + i);
    }
}

void poly_vec_l_reduce(PolyVecL *v) {
    for (int i = 0; i < L; i++) {
        poly_reduce(&v->vec[i]);
    }
}
void poly_vec_l_add(PolyVecL *w, PolyVecL *u, PolyVecL *v) {
    for (int i = 0; i < L; i++) {
        poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}

void poly_vec_l_ntt(PolyVecL *v) {
    for (int i = 0; i < L; i++) {
        poly_ntt(&v->vec[i]);
    }
}

void poly_vec_l_inv_ntt_to_mont(PolyVecL *v) {
    for (int i = 0; i < L; i++) {
        poly_inv_ntt_to_mont(&v->vec[i]);
    }
}

void poly_vec_l_pointwise_poly_montgomery(PolyVecL *r, Poly *a, PolyVecL *v) {
    for (int i = 0; i < L; i++) {
        poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
    }
}

ErrorCode poly_vec_matrix_expand(PolyVecL (*mat)[K], uint8_t (*rho)[SEED_BYTES]) {
    for (int i = 0; i < K; i++) {
        for (int j = 0; j < L; j++) {
            int err = poly_uniform(&(*mat)[i].vec[j], rho, ((uint16_t) i << 8) + (uint16_t) j);
            if (err != 0) {
                return err;
            }
        }
    }
    return 0;
}

int32_t poly_vec_l_chk_norm(volatile PolyVecL *v, int32_t bound) {
    for (int i = 0; i < L; i++) {
        int err = poly_chk_norm((Poly *) &v->vec[i], bound);
        if (err != 0) {
            return 1;
        }
    }

    return 0;
}

void poly_vec_k_add(PolyVecK *w, PolyVecK *u, PolyVecK *v) {
    for (int i = 0; i < K; i++) {
        poly_add(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}

void poly_vec_k_sub(PolyVecK *w, PolyVecK *u, PolyVecK *v) {
    for (int i = 0; i < K; i++) {
        poly_sub(&w->vec[i], &u->vec[i], &v->vec[i]);
    }
}
void poly_vec_k_shift_l(PolyVecK *v) {
    for (int i = 0; i < K; i++) {
        poly_shitf_l(&v->vec[i]);
    }
}

void poly_vec_k_ntt(PolyVecK *v) {
    for (int i = 0; i < K; i++) {
        poly_ntt(&v->vec[i]);
    }
}

void poly_vec_k_inv_ntt_to_mont(PolyVecK *v) {
    for (int i = 0; i < K; i++) {
        poly_inv_ntt_to_mont(&v->vec[i]);
    }
}

void poly_vec_k_pointwise_poly_montgomery(PolyVecK *r, Poly *a, PolyVecK *v) {
    for (int i = 0; i < K; i++) {
        poly_pointwise_montgomery(&r->vec[i], a, &v->vec[i]);
    }
}

int32_t poly_vec_k_chk_norm(volatile PolyVecK *v, int32_t bound) {
    for (int i = 0; i < K; i++) {
        int err = poly_chk_norm((Poly *) &v->vec[i], bound);
        if (err != 0) {
            return 1;
        }
    }
    return 0;
}

void poly_vec_k_power2_round(PolyVecK *v1, PolyVecK *v0, PolyVecK *v) {
    for (int i = 0; i < K; i++) {
        poly_power2_round(&v1->vec[i], &v0->vec[i], &v->vec[i]);
    }
}

void poly_vec_k_decompose(PolyVecK *v1, PolyVecK *v0, PolyVecK *v) {
    for (int i = 0; i < K; i++) {
        poly_decompose(&v1->vec[i], &v0->vec[i], &v->vec[i]);
    }
}

uint32_t poly_vec_k_make_hint(PolyVecK *h, PolyVecK *v0, PolyVecK *v1) {
    uint32_t s = 0;
    for (int i = 0; i < K; i++) {
        s += poly_make_hint(&h->vec[i], &v0->vec[i], &v1->vec[i]);
    }
    return s;
}

void poly_vec_k_use_hint(PolyVecK *w, PolyVecK *u, PolyVecK *h) {
    for (int i = 0; i < K; i++) {
        poly_use_hint(&w->vec[i], &u->vec[i], &h->vec[i]);
    }
}

void poly_vec_l_pointwise_acc_montgomery(Poly *w, PolyVecL *u, PolyVecL *v) {
    Poly t;
    explicit_bzero(&t, sizeof(t));

    poly_pointwise_montgomery(w, &u->vec[0], &v->vec[0]);
    for (int i = 1; i < L; i++) {
        poly_pointwise_montgomery(&t, &u->vec[i], &v->vec[i]);
        poly_add(w, w, &t);
    }
    explicit_bzero(&t, sizeof(t));
}

void poly_vec_matrix_pointwise_montgomery(PolyVecK *t, PolyVecL (*mat)[K], PolyVecL *v) {
    for (int i = 0; i < K; i++) {
        poly_vec_l_pointwise_acc_montgomery(&t->vec[i], &(*mat)[i], v);
    }
}

ErrorCode poly_vec_l_uniform_eta(PolyVecL *v, uint8_t (*seed)[CRH_BYTES], uint16_t nonce) {
    for (int i = 0; i < L; i++) {
        int err = poly_uniform_eta(&v->vec[i], seed, nonce);
        if (err != 0) {
            return err;
        }
        nonce++;
    }
    return 0;
}
ErrorCode poly_vec_k_uniform_eta(PolyVecK *v, uint8_t (*seed)[CRH_BYTES], uint16_t nonce) {
    for (int i = 0; i < K; i++) {
        int err = poly_uniform_eta(&v->vec[i], seed, nonce);
        if (err != 0) {
            return err;
        }
        nonce++;
    }
    return 0;
}

void poly_vec_k_reduce(PolyVecK *v) {
    for (int i = 0; i < K; i++) {
        poly_reduce(&v->vec[i]);
    }
}
void poly_vec_k_c_addq(PolyVecK *v) {
    for (int i = 0; i < K; i++) {
        poly_c_addq(&v->vec[i]);
    }
}

ErrorCode poly_vec_k_pack_w1(uint8_t *r, size_t r_len, PolyVecK *w1) {
    if (r_len != K * POLY_W1_PACKED_BYTES) {
        return ERR_INVALID_LENGTH;
    }
    for (int i = 0; i < K; i++) {
        r = r + i * POLY_W1_PACKED_BYTES;
        poly_w1_pack(r, &w1->vec[i]);
    }
    return 0;
}
