#include "openfhe.h"
#include <bits/stdc++.h>

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

using namespace lbcrypto;
using namespace std;

// TODO: set SID as last 3 digits of your student id without tilling zeros
const double SID = 102;

uint32_t multDepth = 1;
uint32_t scaleModSize = 50;
uint32_t batchSize = 256;

int main() {
  // input
  int n;
  cin >> n;
  vector<double> a(n), b(n);
  for (int i = 0; i < n; i++) {
    cin >> a[i];
  }
  for (int i = 0; i < n; i++) {
    cin >> b[i];
  }

  // initialize the context
  CCParams<CryptoContextCKKSRNS> parameters;
  parameters.SetMultiplicativeDepth(multDepth);
  parameters.SetScalingModSize(scaleModSize);
  parameters.SetBatchSize(batchSize);
  CryptoContext<DCRTPoly> context = GenCryptoContext(parameters);
  context->Enable(PKE);
  context->Enable(KEYSWITCH);
  context->Enable(LEVELEDSHE);

  // initialize the keys
  KeyPair<DCRTPoly> keyPair;
  keyPair = context->KeyGen();
  context->EvalMultKeyGen(keyPair.secretKey);

  // TODO: pack vectors a and b as plaintexts
  Plaintext ptx_a;
  Plaintext ptx_b;
  ptx_a = context->MakeCKKSPackedPlaintext(a);
  ptx_b = context->MakeCKKSPackedPlaintext(b);

  // TODO: pack SID as a plaintext
  vector<double> vec_SID(n);
  fill(vec_SID.begin(), vec_SID.end(), SID);
  Plaintext ptx_SID;
  ptx_SID = context->MakeCKKSPackedPlaintext(vec_SID);

  // TODO: encrypt plaintexts as ciphertexts
  Ciphertext<DCRTPoly> ctx_a;
  Ciphertext<DCRTPoly> ctx_b;
  ctx_a = context->Encrypt(keyPair.publicKey, ptx_a);
  ctx_b = context->Encrypt(keyPair.publicKey, ptx_b);


  // TODO: calculate ctx_result = (ctx_a + SID) * ctx_b
  Ciphertext<DCRTPoly> ctx_result;
  ctx_result = context->EvalAdd(ctx_a, ptx_SID);
  ctx_result = context->EvalMultAndRelinearize(ctx_result, ctx_b);
  ctx_result = context->Rescale(ctx_result);

  // serialize
  Serial::SerializeToFile("q1-1_context", context, SerType::BINARY);
  Serial::SerializeToFile("q1-1_ctx_result", ctx_result, SerType::BINARY);
  Serial::SerializeToFile("q1-1_secret_key", keyPair.secretKey,
                          SerType::BINARY);
}