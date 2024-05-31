#include "openfhe.h"

#include "scheme/bfvrns/bfvrns-cryptoparameters.h"
#include "schemerns/rns-pke.h"
#include "cryptocontext.h"

using namespace lbcrypto;


Poly bfv_get_secret_noise(CryptoContext<DCRTPoly>& cc, ConstCiphertext<DCRTPoly> ciphertext, const PrivateKey<DCRTPoly> privateKey) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(privateKey->GetCryptoParameters());
    DCRTPoly b = cc->GetScheme()->DecryptCore(ciphertext, privateKey);
    b.SetFormat(Format::COEFFICIENT);
    return b.CRTInterpolate();
}

NativeInteger bfv_get_secret_noise_coef_i(CryptoContext<DCRTPoly>& cc, ConstCiphertext<DCRTPoly> ciphertext, uint64_t i, const PrivateKey<DCRTPoly> privateKey) {
    Poly bpoly = bfv_get_secret_noise(cc, ciphertext, privateKey);
    BigInteger bcoef0 = bpoly.at(i);
    if (bcoef0 > (bpoly.GetModulus() >> 1))
      bcoef0 = bpoly.GetModulus() - bcoef0;
    return (NativeInteger)bcoef0;
}

// int main() {
int main(int argc, char* argv[]) {
  if (argc == 1) {
    std::cout << R"message(
Usage:

./bfv_simple_example <m> <t> <sigma>
)message" << std::endl;
    return 0;
  }

  usint m = std::atol(argv[1]);	  // e.g. 1000
  PlaintextModulus p = std::atol(argv[2]);	  // e.g. 53
  float sigma = std::atol(argv[3]); // e.g. 150
  bool verbose = false;
  if (argc>4) {
    std::string argv4(argv[4]);
    verbose = (argv4 == "-v") ? true : false;
  }

  // Set CryptoContext
  CCParams<CryptoContextBFVRNS> parameters;
  parameters.SetRingDim(m);	// 8192
  parameters.SetPlaintextModulus(p); // 1024
  parameters.SetSecurityLevel(lbcrypto::SecurityLevel::HEStd_128_classic);
  parameters.SetStandardDeviation(sigma);
  parameters.SetSecretKeyDist(UNIFORM_TERNARY);
  //parameters.SetMultiplicativeDepth(0);
  //parameters.SetBatchSize(1);
  //parameters.SetDigitSize(digitSize);
  //parameters.SetScalingModSize(dcrtBits);
  if(verbose) std::cout<<"SecurityLevel: "<<parameters.GetSecurityLevel()<<".\n";


  CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

  // enable features that you wish to use
  cc->Enable(PKE);
  //cc->Enable(KEYSWITCH);
  cc->Enable(LEVELEDSHE);
  cc->Enable(ADVANCEDSHE);

  m = cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder();  // should be same
  usint n = m/2;
  auto q = cc->GetCryptoParameters()->GetElementParams()->GetModulus();
  size_t qDgtLength = log2(q.ConvertToDouble())/log2(10);

  // Print out the parameters
  if(verbose){
    std::cerr << "p = " << m << std::endl;
    std::cerr << "n = " << n << std::endl;
    std::cerr << "q = " << q << std::endl;
    std::cerr << "log2 q = " << log2(q.ConvertToDouble()) << std::endl;
    std::cerr << "q digit length = " << qDgtLength << std::endl;
  }

  // Keys
  KeyPair<DCRTPoly> keyPair;
  keyPair = cc->KeyGen();
  if (!keyPair.good() && verbose){
    std::cerr << "Key generation failed!" << std::endl; exit(1);
  }

  // Plaintext
  Plaintext pt = cc->MakeCoefPackedPlaintext({0});
  if (verbose) std::cerr << "pt: " << pt << std::endl;

  // Encryption
  Ciphertext<DCRTPoly> ciphertext;
  ciphertext = cc->Encrypt(keyPair.publicKey, pt);   

  //Get the DCRTPoly of the ciphertext
  auto elements = ciphertext->GetElements();
  DCRTPoly b = elements[0];
  DCRTPoly a = elements[1];

  a.SetFormat(Format::COEFFICIENT);
  b.SetFormat(Format::COEFFICIENT);

  // Interpolate a DCRTPoly to get a aPoly
  Poly aPoly = a.CRTInterpolate();
  // Interpolate b DCRTPoly to get a bPoly
  Poly bPoly = b.CRTInterpolate();

  // Function to get the noise poly (forbidden action)
  Poly noisePoly = bfv_get_secret_noise(cc, ciphertext, keyPair.secretKey);

  //Get the first coefficient of the interpolated Poly
  BigInteger bcoef0 = bPoly.at(0);
  // if (bcoef0 > (bPoly.GetModulus() >> 1))
  //   bcoef0 = bPoly.GetModulus() - bcoef0;
  // if(verbose) std::cout << " > coef0 of b = " << ((NativeInteger)bcoef0) << "\n";

  
  size_t idxWidth = 6;
  size_t sep = 3;		// width of separaor " | "
  size_t qWidth = qDgtLength + 3;
  size_t noiseWidth = 8;
  std::cout << std::right << std::setw(idxWidth) << "idx";
  std::cout << " | ";
  std::cout << std::right << std::setw(qWidth) << "a";
  std::cout << std::right << std::setw(qWidth) << "(nativeinteger)";
  std::cout << " | ";
  std::cout << std::right << std::setw(qWidth) << "b";
  std::cout << std::right << std::setw(qWidth) << "(nativeinteger)";
  std::cout << " | ";
  std::cout << std::right << std::setw(noiseWidth) << "noise";
  std::cout << std::endl;

  size_t totalWidth = \
    idxWidth	      \
    + 3*sep \
    + 4*qWidth \
    + noiseWidth;


  std::cout << std::string(totalWidth, '-') << std::endl;
  size_t loopN = n;
  for (size_t i=0; i<loopN; ++i) {

    BigInteger aCoef = aPoly.at(i);
    if (aCoef > (q>>1)) aCoef = q - aCoef;

    BigInteger bCoef = bPoly.at(i);
    if (bCoef > (q>>1)) bCoef = q - bCoef;

    BigInteger noiseCoef = noisePoly.at(i);
    if (noiseCoef > (q>>1)) noiseCoef = q - noiseCoef;
    
    std::cout << std::right << std::setw(idxWidth) << i;
    std::cout << " | ";
    std::cout << std::right << std::setw(qWidth) << aCoef;
    std::cout << std::right << std::setw(qWidth) << (NativeInteger)aCoef;
    std::cout << " | ";
    std::cout << std::right << std::setw(qWidth) << bCoef;
    std::cout << std::right << std::setw(qWidth) << (NativeInteger)bCoef;
    std::cout << " | ";
    std::cout << std::right << std::setw(noiseWidth) << noiseCoef;
    std::cout << std::endl;
  }

  return 0;
}
