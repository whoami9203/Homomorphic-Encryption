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

int main() {
  // deserialize context
  CryptoContext<DCRTPoly> context;
  context->ClearEvalMultKeys();
  Serial::DeserializeFromFile("q1-2_context", context, SerType::BINARY);

  // deserialize mult_key
  ifstream multKeyIStream("q1-2_mult_key", ios::in | ios::binary);
  context->DeserializeEvalMultKey(multKeyIStream, SerType::BINARY);

  // deserialize ciphertexts
  Ciphertext<DCRTPoly> ctx_p, ctx_q;
  Serial::DeserializeFromFile("q1-2_ctx_p", ctx_p, SerType::BINARY);
  Serial::DeserializeFromFile("q1-2_ctx_q", ctx_q, SerType::BINARY);

  // TODO: pack SID as a plaintext
  vector<double> vec_SID(256); // please don't modify the number 256
  fill(vec_SID.begin(), vec_SID.end(), SID);
  Plaintext ptx_SID = context->MakeCKKSPackedPlaintext(vec_SID);

  // TODO: calculate ctx_result = (ctx_p + SID) * ctx_q
  Ciphertext<DCRTPoly> ctx_result;
  ctx_result = context->EvalAdd(ctx_p, ptx_SID);
  ctx_result = context->EvalMultAndRelinearize(ctx_result, ctx_q);
  ctx_result = context->Rescale(ctx_result);

  // serialize
  Serial::SerializeToFile("q1-2_ctx_result", ctx_result, SerType::BINARY);
}