#include "openfhe.h"
#include <bits/stdc++.h>

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

using namespace lbcrypto;
using namespace std;

// in Q2, you don't have to modify this
const double SID = 123;

uint32_t multDepth = 30;
uint32_t scaleModSize = 50;
uint32_t batchSize = 256;

int main() {
  int T = 5;
  vector<Ciphertext<DCRTPoly>> ctx_results(T);
  int start_time = time(0);

  // input
  srand(214748); // please don't modify this line
  int n = batchSize;
  vector<double> a(n), b(n);
  for (int i = 0; i < n; i++) {
    a[i] = 10.0 * (double)rand() / (RAND_MAX + 1.0);
    b[i] = 10.0 * (double)rand() / (RAND_MAX + 1.0);
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

  Plaintext ptx_a, ptx_b, ptx_SID, ptx_result;
  Ciphertext<DCRTPoly> ctx_a, ctx_b, ctx_result;
  vector<double> result;

  for (int t = 0; t < T; t++) {
    // TODO: pack vectors a and b as plaintexts
    ptx_a = MakeCKKSPackedPlaintext(a);
    ptx_b = MakeCKKSPackedPlaintext(b);

    // TODO: pack SID as a plaintext
    vector<double> vec_SID(n);
    fill(vec_SID.begin(), vec_SID.end(), SID);
    ptx_SID = MakeCKKSPackedPlaintext(vec_SID);

    // TODO: encrypt plaintexts as ciphertexts
    ctx_a = context->Encrypt(ptx_a);
    ctx_b = context->Encrypt(ptx_b);

    // TODO: calculate ctx_result = (ctx_a + SID) * ctx_b
    ctx_result = context->EvalAdd(ctx_a, ptx_SID);
    ctx_result = context->EvalMultAndRelinearize(ctx_result, ctx_b);

    context->Decrypt(keyPair.secretKey, ctx_result, &ptx_result);
    ptx_result->SetLength(n);
    result = ptx_result->GetRealPackedValue();
  }
  int end_time = time(0);

  double error = 0;
  for (int i = 0; i < n; i++) {
    error += abs((a[i] + SID) * b[i] - result[i]);
  }

  cout << "time: " << end_time - start_time << " secs" << endl;
  cout << "average error: " << error / n << " = 2 ^ "
       << (int)log2(error / n) << endl;
}