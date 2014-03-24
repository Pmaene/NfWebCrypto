/*
 *
 *  Copyright 2013 Netflix, Inc.
 *
 *     Licensed under the Apache License, Version 2.0 (the "License");
 *     you may not use this file except in compliance with the License.
 *     You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *     Unless required by applicable law or agreed to in writing, software
 *     distributed under the License is distributed on an "AS IS" BASIS,
 *     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *     See the License for the specific language governing permissions and
 *     limitations under the License.
 *
 */
#include "DiffieHellmanContext.h"
#include <assert.h>
#include <algorithm>
#include <string>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <base/DebugUtil.h>
#include <crypto/NtbaUtil.h>
#include <crypto/BigNum.h>
#include <crypto/OpenSSLException.h>
#include <crypto/ScopedOpenSSL.h>

using namespace std;
using namespace cadmium::base;

namespace cadmium {
namespace crypto {

DiffieHellmanContext::DiffieHellmanContext()
:   pOsslDh_(NULL)
{
}

DiffieHellmanContext::~DiffieHellmanContext()
{
    if (pOsslDh_)
        DH_free(pOsslDh_);
}

bool DiffieHellmanContext::init(const Vuc& p, const Vuc& g)
{
    // this method clobbers any existing context
    if (pOsslDh_)
        DH_free(pOsslDh_);

    // create a new DH
    pOsslDh_ = DH_new();
    if (!pOsslDh_)
    {
        DLOG() << "DiffieHellmanContext::init: Unable to create DH using DH_new()\n";
        return false;
    }

    // ensure p is 1024 bits - this is a requirement to get a 128-bit key for AES
    if (p.size() != 128)
    {
        DLOG() << "DiffieHellmanContext::init: p is not 1024 bits\n";
        return false;
    }

    // DH_new creates a DH with p & g set to NULL; copy in our new values
    if (!(pOsslDh_->p = BN_dup(BigNum(p).getBIGNUM())))
    {
        DLOG() << "DiffieHellmanContext::init: Unable to duplicate DH prime using BN_dup()\n";
        return false;
    }
    if (!(pOsslDh_->g = BN_dup(BigNum(g).getBIGNUM())))
    {
        DLOG() << "DiffieHellmanContext::init: Unable to duplicate DH generator using BN_dup()\n";
        return false;
    }

    return true;
}

bool DiffieHellmanContext::generate(const Vuc& p, const Vuc& g)
{
    // initialize the DH context
    if (!DiffieHellmanContext::init(p, g))
    {
        DLOG() << "DiffieHellmanContext::generate: initialisation failed\n";
        return false;
    }

    // generate the pub/priv key pair
    if (!DH_generate_key(pOsslDh_))
    {
        DLOG() << "DiffieHellmanContext::generate: failed\n";
        return false;
    }

    return true;
}

DiffieHellmanContext::Vuc DiffieHellmanContext::getPublicRaw() const
{
    return BigNum(pOsslDh_->pub_key).encode();
}

bool DiffieHellmanContext::setPrivateRaw(const Vuc& p, const Vuc& g, const Vuc& priv_key)
{
    // initialize the DH context
    if (!DiffieHellmanContext::init(p, g))
    {
        DLOG() << "DiffieHellmanContext::setPrivateRaw: initialisation failed\n";
        return false;
    }

    BIGNUM *q = BigNum(p).getBIGNUM();
    BN_sub_word(q, 1);
    pOsslDh_->pub_key = BN_dup(q);

    if (!(pOsslDh_->priv_key = BN_dup(BigNum(priv_key).getBIGNUM())))
    {
        DLOG() << "DiffieHellmanContext::setPrivateRaw: Unable to duplicate DH private key using BN_dup()\n";
        return false;
    }

    return true;
}

DiffieHellmanContext::Vuc DiffieHellmanContext::getPrivateRaw() const
{
    return BigNum(pOsslDh_->priv_key).encode();
}

bool DiffieHellmanContext::setPublicSpki(const Vuc& pubKeySpkiDer)
{
    return false;
}

bool DiffieHellmanContext::getPublicSpki(Vuc& pubKeySpkiDer) const
{
    return false;
}

bool DiffieHellmanContext::setPrivatePkcs8(const Vuc& pkcs8)
{
    // OpenSSL does not make it easy to import a private key in PKCS#8 format.
    // Must go through some monkey-motions.

    // make a mem BIO pointing to the incoming PKCS#8 data
    char* const data = reinterpret_cast<char*>(const_cast<uint8_t*>(&pkcs8[0]));
    ScopedOpenSSL<BIO, BIO_free_all> bio(BIO_new_mem_buf(data, pkcs8.size()));
    if (!bio.get())
    {
        OPENSSLERROR_MSG("DiffieHellmanContext::setPrivatePkcs8: BIO_new_mem_buf() failed");
        return false;
    }

    // get a PKCS8_PRIV_KEY_INFO struct from the BIO
    ScopedOpenSSL<PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_free> p8inf(
        d2i_PKCS8_PRIV_KEY_INFO_bio(bio.get(), NULL));
    if (!p8inf.get())
    {
        OPENSSLERROR_MSG("DiffieHellmanContext::setPrivatePkcs8: d2i_PKCS8_PRIV_KEY_INFO_bio() failed");
        return false;
    }

    // create a EVP_PKEY from the PKCS8_PRIV_KEY_INFO
    ScopedOpenSSL<EVP_PKEY, EVP_PKEY_free> pkey(EVP_PKCS82PKEY(p8inf.get()));
    if (!pkey.get())
    {
        OPENSSLERROR_MSG("DiffieHellmanContext::setPrivatePkcs8: EVP_PKCS82PKEY() failed");
        return false;
    }

    // get the DH struct from the EVP_PKEY
    DH * const dh = EVP_PKEY_get1_DH(pkey.get());
    if (!dh)
    {
        OPENSSLERROR_MSG("DiffieHellmanContext::setPrivatePkcs8: EVP_PKEY_get1_DH() failed");
        return false;
    }

    // save the DH struct to this
    pOsslDh_ = dh;
    return true;
}

bool DiffieHellmanContext::getPrivatePkcs8(Vuc& pkcs8) const
{
    if (!pOsslDh_->priv_key)
        return false;
    ScopedOpenSSL<EVP_PKEY, EVP_PKEY_free> pkey(EVP_PKEY_new());
    if (pkey.get() == NULL)
    {
        OPENSSLERROR_MSG("DiffieHellmanContext::getPrivatePkcs8: EVP_PKEY_new() failed");
        return false;
    }
    int ret = EVP_PKEY_set1_DH(pkey.get(), pOsslDh_);
    if (!ret)
    {
        OPENSSLERROR_MSG("DiffieHellmanContext::getPrivatePkcs8: EVP_PKEY_set1_DH() failed");
        return false;
    }
    ScopedOpenSSL<PKCS8_PRIV_KEY_INFO, PKCS8_PRIV_KEY_INFO_free> p8inf(EVP_PKEY2PKCS8(pkey.get()));
    if (p8inf.get() == NULL)
    {
        OPENSSLERROR_MSG("DiffieHellmanContext::getPrivatePkcs8: EVP_PKEY2PKCS8() failed");
        return false;
    }
    int outLen = i2d_PKCS8_PRIV_KEY_INFO(p8inf.get(), NULL);
    if (outLen <= 0)
    {
        OPENSSLERROR_MSG("DiffieHellmanContext::getPrivatePkcs8: i2d_PKCS8_PRIV_KEY_INFO() returned bad length");
        return false;
    }
    pkcs8.resize(outLen);
    unsigned char * buf = &pkcs8[0];
    ret = i2d_PKCS8_PRIV_KEY_INFO(p8inf.get(), &buf);
    if (!ret)
    {
        OPENSSLERROR_MSG("DiffieHellmanContext::i2d_PKCS8_PRIV_KEY_INFO: EVP_PKEY_set1_DH() failed");
        return false;
    }
    return true;
}

bool DiffieHellmanContext::computeSharedSecret(const Vuc& peerPubKey)
{
    // make sure we have a pub/priv key
    if(!pOsslDh_->priv_key)
    {
        DLOG() << "DiffieHellmanContext::computeSharedSecret: missing local key\n";
        return false;
    }

    if (!peerPubKey.size())
    {
        DLOG() << "DiffieHellmanContext::computeSharedSecret: missing peer key\n";
        return false;
    }

    // get size needed for shared secret
    int outLen = DH_size(pOsslDh_);
    if(outLen != 128)
    {
        DLOG() << "DiffieHellmanContext::computeSharedSecret: shared secret (DH_size) not 128 bytes\n";
        return false;
    }
    // allocate and zero space for the shared secret
    sharedSecret_ = Vuc(outLen, 0);

    // compute the shared secret
    outLen = DH_compute_key(&sharedSecret_[0], BigNum(peerPubKey).getBIGNUM(), pOsslDh_);
    if(outLen == -1 || outLen > 128)
    {
        DLOG() << ERR_error_string(ERR_get_error(), NULL) << "\n";
        DLOG() << "DiffieHellmanContext::computeSharedSecret: error computing shared secret\n";
        return false;
    }
    // The computed shared secret may be less than 128 bytes so resize it.
    Vuc(sharedSecret_.begin(), sharedSecret_.begin()+outLen).swap(sharedSecret_); // shrink to fit

    return true;
}

DiffieHellmanContext::Vuc DiffieHellmanContext::getSharedSecret() const
{
    return sharedSecret_;
}

}} // namespace cadmium::crypto
