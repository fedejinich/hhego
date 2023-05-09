package examples

import (
	"fmt"
	hhegobfv "hhego/bfv"
	"hhego/pasta"
	"hhego/util"
	"testing"
)

var PastaParams = pasta.Params{SecretKeySize: pasta.SecretKeySize, PlaintextSize: pasta.PlaintextSize,
	CiphertextSize: pasta.CiphertextSize, Rounds: 3}

const (
	PackedUseCase = iota
	Dec
	PackedUseCaseLarge
)

type TestCase struct {
	testType           int
	pastaSecretKey     []uint64
	ciphertextExpected []uint64
	plainMod           uint64
	modDegree          uint64
	secLevel           uint64
	matrixSize         uint64
	plaintext          []uint64
	bsgN1              uint64
	bsgN2              uint64
	useBsGs            bool
}

func TestSingleParty(t *testing.T) {
	for i, tc := range testCases(false) {
		switch tc.testType {
		case PackedUseCase, PackedUseCaseLarge:
			t.Run(fmt.Sprintf("TestPackedUseCase%d", i), func(t *testing.T) {
				packedTest(t, tc.pastaSecretKey, tc.plaintext, tc.plainMod, tc.modDegree, tc.secLevel,
					tc.matrixSize, tc.bsgN1, tc.bsgN2, tc.useBsGs)
			})
		case Dec:
			t.Errorf("not implemented yet")
		default:
			t.Errorf("no test case")
		}
	}

}

func packedTest(t *testing.T, pastaSecretKey, plaintext []uint64, plainMod, modDegree, secLevel, matrixSize,
	bsgN1, bsgN2 uint64, useBsGs bool) {

	// create pasta cipher
	pastaCipher := pasta.NewPasta(pastaSecretKey, plainMod, PastaParams)

	// create bfv cipher
	bfvPastaParams := hhegobfv.PastaParams{
		PastaRounds:         int(PastaParams.Rounds),
		PastaCiphertextSize: int(PastaParams.CiphertextSize),
		Modulus:             int(plainMod),
	}
	bfv := hhegobfv.NewBFVPasta(bfvPastaParams, modDegree, secLevel, matrixSize, bsgN1, bsgN2, useBsGs, plainMod)
	pastaCiphertext := pastaCipher.Encrypt(plaintext)

	// homomorphically encrypt secret key
	pastaSKCiphertext := bfv.EncryptPastaSecretKey(pastaSecretKey)

	// move from PASTA ciphertext to BFV ciphertext
	bfvCiphertext := bfv.Transcipher(pastaCiphertext, pastaSKCiphertext)

	// homomorphically evaluation

	// final decrypt
	decrypted := bfv.DecryptPacked(&bfvCiphertext, matrixSize)
	if !util.EqualSlices(decrypted, plaintext) {
		t.Errorf("decrypted a different vector")
		fmt.Printf("matrixSize = %d\n", matrixSize)
		fmt.Printf("plainMod = %d\n", plainMod)
		fmt.Printf("secLevel = %d\n", secLevel)
		//fmt.Printf("bsgsN1 = %d\n", bsgN1)
		//fmt.Printf("bsgsN2 = %d\n", bsgN2)
		//fmt.Printf("useBsGs = %v\n", useBsGs)
	}
}

func testCases(enableLargeTestCases bool) []TestCase {
	cases := []TestCase{
		{
			pastaSecretKey: []uint64{0x07a30, 0x0cfe2, 0x03bbb, 0x06ab7, 0x0de0b, 0x0c36c, 0x01c39, 0x019e0,
				0x0e09c, 0x04441, 0x0c560, 0x00fd4, 0x0c611, 0x0a3fd, 0x0d408, 0x01b17,
				0x0fa02, 0x054ea, 0x0afeb, 0x0193b, 0x0b6fa, 0x09e80, 0x0e253, 0x03f49,
				0x0c8a5, 0x0c6a4, 0x0badf, 0x0bcfc, 0x0ecbd, 0x06ccd, 0x04f10, 0x0f1d6,
				0x07da9, 0x079bd, 0x08e84, 0x0b774, 0x07435, 0x09206, 0x086d4, 0x070d4,
				0x04383, 0x05d65, 0x0b015, 0x058fe, 0x0f0d1, 0x0c700, 0x0dc40, 0x02cea,
				0x096db, 0x06c84, 0x008ef, 0x02abc, 0x03fdf, 0x0ddaf, 0x028c7, 0x0ded4,
				0x0bb88, 0x020cd, 0x075c3, 0x0caf7, 0x0a8ff, 0x0eadd, 0x01c02, 0x083b1,
				0x0a439, 0x0e2db, 0x09baa, 0x02c09, 0x0b5ba, 0x0c7f5, 0x0161c, 0x0e94d,
				0x0bf6f, 0x070f1, 0x0f574, 0x0784b, 0x08cdb, 0x08529, 0x027c9, 0x010bc,
				0x079ca, 0x01ff1, 0x0219a, 0x00130, 0x0ff77, 0x012fb, 0x03ca6, 0x0d27d,
				0x05747, 0x0fa91, 0x00766, 0x04f27, 0x00254, 0x06e8d, 0x0e071, 0x0804e,
				0x08b0e, 0x08e59, 0x04cd8, 0x0485f, 0x0bde0, 0x03082, 0x01225, 0x01b5f,
				0x0a83e, 0x0794a, 0x05104, 0x09c19, 0x0fdcf, 0x036fe, 0x01e41, 0x00038,
				0x086e8, 0x07046, 0x02c07, 0x04953, 0x07869, 0x0e9c1, 0x0af86, 0x0503a,
				0x00f31, 0x0535c, 0x0c2cb, 0x073b9, 0x028e3, 0x03c2b, 0x0cb90, 0x00c33,
				0x08fe7, 0x068d3, 0x09a8c, 0x008e0, 0x09fe8, 0x0f107, 0x038ec, 0x0b014,
				0x007eb, 0x06335, 0x0afcc, 0x0d55c, 0x0a816, 0x0fa07, 0x05864, 0x0dc8f,
				0x07720, 0x0deef, 0x095db, 0x07cbe, 0x0834e, 0x09adc, 0x0bab8, 0x0f8f7,
				0x0b21a, 0x0ca98, 0x01a6c, 0x07e4a, 0x04545, 0x078a7, 0x0ba53, 0x00040,
				0x09bc5, 0x0bc7a, 0x0401c, 0x00c30, 0x00000, 0x0318d, 0x02e95, 0x065ed,
				0x03749, 0x090b3, 0x01e23, 0x0be04, 0x0b612, 0x08c0c, 0x06ea3, 0x08489,
				0x0a52c, 0x0aded, 0x0fd13, 0x0bd31, 0x0c225, 0x032f5, 0x06aac, 0x0a504,
				0x0d07e, 0x0bb32, 0x08174, 0x0bd8b, 0x03454, 0x04075, 0x06803, 0x03df5,
				0x091a0, 0x0d481, 0x09f04, 0x05c54, 0x0d54f, 0x00344, 0x09ffc, 0x00262,
				0x01fbf, 0x0461c, 0x01985, 0x05896, 0x0fedf, 0x097ce, 0x0b38d, 0x0492f,
				0x03764, 0x041ad, 0x02849, 0x0f927, 0x09268, 0x0bafd, 0x05727, 0x033bc,
				0x03249, 0x08921, 0x022da, 0x0b2dc, 0x0e42d, 0x055fa, 0x0a654, 0x073f0,
				0x08df1, 0x08149, 0x00d1b, 0x0ac47, 0x0f304, 0x03634, 0x0168b, 0x00c59,
				0x09f7d, 0x0596c, 0x0d164, 0x0dc49, 0x038ff, 0x0a495, 0x07d5a, 0x02d4,
				0x06c6c, 0x0ea76, 0x09af5, 0x0bea6, 0x08eea, 0x0fbb6, 0x09e45, 0x0e9db,
				0x0d106, 0x0e7fd, 0x04ddf, 0x08bb8, 0x0a3a4, 0x03bcd, 0x036d9, 0x05acf},
			ciphertextExpected: []uint64{0x00},
			plainMod:           65537,
			modDegree:          32768,
			secLevel:           128,
			matrixSize:         200,
			plaintext:          hhegobfv.RandomInputV(200, uint64(65537)),
			bsgN1:              20,
			bsgN2:              10,
			useBsGs:            true,
		},
		{testType: PackedUseCase,
			pastaSecretKey: []uint64{0x02d65ac52, 0x1c6b45d1c, 0x1cb39041d, 0x0a114487b, 0x1bd58169e,
				0x06687bfc2, 0x0f2ca10ae, 0x08147165f, 0x145bd33c0, 0x1d93385c2,
				0x045108f23, 0x0d464ef68, 0x162009aed, 0x0bb4cf340, 0x0a963c1ee,
				0x08b633c3a, 0x13b1c1deb, 0x0275b464a, 0x170637204, 0x06b6f143c,
				0x14e2017d2, 0x13b9362c0, 0x099369b1a, 0x0381dcd7b, 0x09e4472db,
				0x12590d316, 0x139fbf37f, 0x13e35f2e8, 0x0ca7d4585, 0x1db99dd9a,
				0x094be46a2, 0x1ad06c1dd, 0x0bc081dab, 0x1b07b4ec2, 0x123f5d89d,
				0x10cee2d6e, 0x1dc263d6c, 0x1c3b3e526, 0x1ae8d01b2, 0x01d7a2071,
				0x1103f4ecc, 0x0cfbfdf86, 0x109d1fbd3, 0x13c50ac85, 0x0f5774d95,
				0x125d635b6, 0x0e064425a, 0x1b0448fbd, 0x01c514347, 0x103c917ad,
				0x1c26ea8ed, 0x059002810, 0x0fa25328b, 0x12b6e9cec, 0x0b4833bbc,
				0x09b81028c, 0x10bd4074a, 0x15c6d6d30, 0x0fda2fd14, 0x1818b77c5,
				0x0481c0638, 0x0223a184b, 0x0e899e472, 0x0db15d2d5, 0x10544a7f0,
				0x10a994c6f, 0x102e0c864, 0x133666b00, 0x05b41ee2b, 0x092cf7eec,
				0x157e5cba6, 0x1896cc763, 0x07879f5d9, 0x113411b28, 0x0d9006a3d,
				0x0b3aa1676, 0x12c2b492b, 0x08ef693b9, 0x19b5b200b, 0x09afe0f64,
				0x07514698d, 0x0e6dd8b29, 0x0cefd33f9, 0x024b8d2d4, 0x07d0d2edf,
				0x1b393e3b8, 0x10d92c1a9, 0x1cce4b9f9, 0x1bc38c79e, 0x0130fbfc6,
				0x13db89aaa, 0x1462d04cc, 0x12175c267, 0x0d6a1510c, 0x0dd64612e,
				0x10b292852, 0x12e6ce66c, 0x13c0a9642, 0x02e0cb677, 0x0c84fa99b,
				0x15812e819, 0x18b4e24d8, 0x1a4d7c750, 0x0ab3d94d3, 0x1c8064423,
				0x049375e2c, 0x1b2637a6d, 0x1644c75f4, 0x15efdf343, 0x0b2ef2066,
				0x00c8cca05, 0x0fcb1085a, 0x1a93d48fe, 0x00de317db, 0x0b74173d8,
				0x1a994f10f, 0x06738549a, 0x0100dca37, 0x0dd50e0e6, 0x1d773fbf3,
				0x1409b9e44, 0x043514748, 0x1bd640aae, 0x0848a36bd, 0x1d9be1ac9,
				0x0b4d29490, 0x19f46714b, 0x1add83450, 0x0f7351561, 0x0e8712cc6,
				0x1b4b20a68, 0x1b6b6b115, 0x0c83e8d78, 0x06ea0ec61, 0x0a54f1dc3,
				0x0fe95ca70, 0x19fc2ef5a, 0x0dc6cce6c, 0x068fb0701, 0x163133330,
				0x19184fabb, 0x1cbf6825c, 0x047cbf057, 0x1a6c7cfaf, 0x1936e87dc,
				0x06462fbc4, 0x1af988ac8, 0x1b285b998, 0x06c4b4e08, 0x130137dd4,
				0x01f05a977, 0x130c75cd6, 0x00a083787, 0x0537d9b83, 0x195dc94bf,
				0x00069d822, 0x062d88ae4, 0x0f0d4f3df, 0x1770c7e1e, 0x03edf347f,
				0x072c6c863, 0x175986f9a, 0x018f7edc0, 0x11f84fa37, 0x0bd25bd71,
				0x162393470, 0x10438585f, 0x08093bb0c, 0x106813829, 0x1a076e502,
				0x109f1e857, 0x1ab3b36f4, 0x00058e9e5, 0x1d1a005a7, 0x1d467ac31,
				0x1942e9dee, 0x1937c8cec, 0x148e414e4, 0x155be0476, 0x00db7a9b2,
				0x0494e79f4, 0x0297f2658, 0x0324fb049, 0x1842cd03c, 0x05681ddd7,
				0x10d6d3414, 0x0bad67d5c, 0x125e6095f, 0x1d2d03a89, 0x0ab867326,
				0x0af59db4e, 0x0a51ce8de, 0x0a44544e4, 0x073ebab3b, 0x0598957f6,
				0x06d37f469, 0x169c1f098, 0x1430cb1e5, 0x04baf5cbd, 0x02f39b481,
				0x196e53b01, 0x1cc261210, 0x0dac027d2, 0x09256ddaf, 0x0c01d5fcf,
				0x0c572bfed, 0x1d2ab209d, 0x0593dc6e1, 0x10afdf699, 0x0e5b8acca,
				0x0d57ee249, 0x05b9ebbd8, 0x1da1868d4, 0x14e12dc8c, 0x02011cca4,
				0x1546c7dca, 0x105247d0c, 0x1a0521d1b, 0x0d472b4e0, 0x133ff9223,
				0x1bc01169a, 0x06d2f5486, 0x099c149a4, 0x1c5e8c80d, 0x0339ee6e4,
				0x10b53583f, 0x12e50b01e, 0x0595fd54a, 0x0b923b738, 0x0809366a0,
				0x0c192d91c, 0x085d8fdf1, 0x1708a3cf9, 0x0f20f4d23, 0x094e780a2,
				0x148524d8e, 0x1a926e993, 0x04837f231, 0x1b7c0cb91, 0x0ee581d07,
				0x0e2f85adc, 0x1c3a4fcc9, 0x1852d298a, 0x053cb1abb, 0x180adbb1f,
				0x114da5af1, 0x08f6e58d0, 0x1a213e8fd, 0x14c8dc340, 0x185b0a047,
				0x10c37657d, 0x19f1f6c3d, 0x15bd1ced2, 0x178b6d3d0, 0x0db1595cc,
				0x0bb77980e},
			plaintext:          hhegobfv.RandomInputV(200, 8088322049),
			ciphertextExpected: []uint64{0x00},
			plainMod:           8088322049,
			modDegree:          32768,
			secLevel:           128,
			matrixSize:         200,
			useBsGs:            true,
			bsgN1:              20,
			bsgN2:              10},
		{
			testType: PackedUseCaseLarge,
			pastaSecretKey: []uint64{0x892f9ff42160c81, 0xa652a61d10eabf3, 0x76bb71c0ddc0c06,
				0xcd4219dc5300904, 0xb555b02f174ea12, 0xaf3a4ea03c081fd,
				0x2e5ca6dc0c3122a, 0x73c7bb66bee9643, 0x68568756417a3da,
				0x50be80234874982, 0xbfb0b39827ac73f, 0x8d81bf84a35fec7,
				0x4c6a515ad3a342e, 0x9222548d6f505bc, 0x154aaa9108d72c9,
				0x5f700f7a2966f4b, 0x51311bfe5e66132, 0xbb1f2488cf388c0,
				0x8923ef9749307f6, 0xc7db00ff85a54c8, 0x45c55a0e561ad54,
				0x0877e89ed848c7d, 0xe584219f06e1eb5, 0xc0207fbdd155b36,
				0x030e34be1a4916b, 0x5ea2bb5315bb2bc, 0xe242363b8e1888a,
				0xd7cd0f83dc0dbbe, 0x1d6f84a7b4f4ae4, 0x3f572774465aac8,
				0x90790b1397e0a14, 0xb34152fe0115879, 0x60b375ae8930c86,
				0x520a8f29a0e8567, 0x6c4ceb278c114c6, 0x34eaea9efbdf10f,
				0xb1d7966e4910f74, 0xb195568e073dab7, 0x39a3a71300f1c89,
				0xc4a1d459b36054a, 0x9ebb00461b68a1e, 0x52c241416d61c2e,
				0xdbcd53c45e512ac, 0xb1625548afe46b4, 0x5cf6e8c1c793d21,
				0xa751b931643bc4a, 0x0cb6456cd70e1da, 0x22ab9c2a8f6b474,
				0xc8720c70727857e, 0x01a26e8335b163d, 0x5285f3756f7ca23,
				0xca030eaced23066, 0x672c2341285025c, 0x18afc3094439aa9,
				0xb680c3d84f433df, 0x1d0ea68d581425b, 0x1cd09c42097117d,
				0x4972fd77469456b, 0xd0d2d16f84bf039, 0x29faba1e7672a70,
				0x5ee86e47992871d, 0x843f42d30f2ce13, 0xdb6c1f645aa71c5,
				0x0b84a30ca6f401a, 0xcf8ead679390b25, 0x3ccf618a1b34f0a,
				0x3fb998a3a37b84b, 0xdffec72a0ab2639, 0x4ad39327f6c0a65,
				0x49543a3664dd857, 0x67c25732b78afab, 0x1cd2a253b3bb7b3,
				0x27891dd76663467, 0x7d354f76cf4fc50, 0x7259c10ee043014,
				0x36129cd1207f768, 0xb955bca043edba9, 0x701a70021a444f9,
				0x9976f1c430465d5, 0xe797036fa297ae0, 0x19a5be62daf7d09,
				0x438d6de681867ef, 0xf0d9aeb988204b0, 0x7ce71a27efad452,
				0xefce163ea1d8d56, 0x6dddb1eaa71d598, 0x62cb3ae78950bec,
				0x27d9c87ba64b8de, 0x72d1f27d152ba7e, 0x78ddd82f940453a,
				0x4b34224491ce139, 0x34341198b57d1f7, 0xb0baeb6d1a3e6d2,
				0x00ebaf5410a2a9e, 0x121dfcbcd9bd6e2, 0xb60a082f03335c8,
				0xe1c85a817ab86d2, 0x9d8ed73030d7e5a, 0x38ac9243b56bfe9,
				0x141f04b1352ab52, 0x3b22818d71d517f, 0x0564454c4a88f08,
				0x9d18d9ab1fbbd4a, 0xa9416b810831904, 0x38cc60cb2e1161f,
				0xae39dad01be4c3f, 0x54f8038061b2abf, 0x9166a28c4368060,
				0x3b899af28a38de5, 0xf09acc8187a56a3, 0x013247429f9f51b,
				0x9adc5fffa69cac4, 0x225652bec6814fe, 0xdaa1b7bd32c5d60,
				0x27886e98288979b, 0x22ad1d2ad81f092, 0xb7067c0d6d64276,
				0x7629dd7467cad88, 0x8d3072e79305da6, 0x624ba51a417c389,
				0x1dcbc3e9eebd85e, 0xc114e4a3a0b644a, 0x6ee23e3cc2cf3f0,
				0xc95e3d69369adec, 0x575ef94e2d8956e, 0x0fb4a1f911f767d,
				0x1df5762dd7b3571, 0x9302b150ad67d44, 0xe3bda67ec878d67,
				0x62d9162332f4c4e, 0x4cce39ee3b6f9e8, 0xc9a21fd7014acda,
				0xef542d33f0361dd, 0xf1158666c84e5f6, 0xc2418a64ce1b871,
				0x1a3718ef0432943, 0x1acce3416d31b67, 0x978644123e266ed,
				0x60d0190bb4eb08a, 0xd7b18102dd6534e, 0xea17c999a91103e,
				0x9d9ae729c8c36cc, 0x34349a44ba7ac9e, 0x19690130559b11e,
				0x287aa1c5640fe38, 0xcb9ee5a34d2646d, 0xc72bcff34b0aef0,
				0x9d554b0c0b8d18c, 0x328ee2e69613bbc, 0xa4e07818eeac88d,
				0x5c4950afa7dbc07, 0x1339bd35b8b8454, 0x8cf7b2cadfcaea1,
				0xbe519bc3ec42453, 0x2408d2795492507, 0xaa110bbb31e085e,
				0x09d0ac1a6884279, 0x25a02dfbcda8780, 0x74f63e314bd5e0b,
				0xcddd7cc1782d0fe, 0x1ec6882ecd2535d, 0x4a6f5d484455cc3,
				0x90bf56cab3867e3, 0x3a521bd770d30f1, 0x381b110169f908d,
				0xb55c79924ef72fd, 0x817bf65abab94a1, 0x6c877a9219ee4ae,
				0x76221d19899227f, 0xa3a38fe6bb8cb5c, 0x794ce42499fd9a4,
				0x56a17de221d3832, 0x0f36eeb67e50936, 0x0d4ce7bd40fd3f6,
				0x57d7c284663cff1, 0x1e1e800e2fe3f81, 0x3258220f24ccd1f,
				0xaf9dd2eaacc8480, 0x34183dad9f3ca6b, 0x28dbf02c1fec25d,
				0xdd52a11f5859ecc, 0x1ce3e8ce1649ca4, 0x11c88d7e76c1812,
				0x1a0344b98cee2f1, 0x8447c6cec074196, 0x520c99c978e1a2c,
				0x9713baf1ce504f3, 0x79b9c17a7169b03, 0xa20c78cb2508455,
				0x4d603a63fe48869, 0x5649e649dd1d078, 0xd6b4c6e1a9afb05,
				0x84c93eac4b8af66, 0x8a193c985be64d4, 0x9d00473749d7c36,
				0xc7f02e7d4c5940b, 0x2298c824123f55e, 0xe4ef5e2906d1f42,
				0xe6e3ac3876ba2ff, 0xd478fae309cd261, 0x61d62f5431f50ba,
				0xda636d7a1c7820b, 0xea4f0fe4b27a917, 0xbd3bffe9da412c0,
				0x48865cf01ac0dc9, 0xc3c99592768b8c0, 0xa3b01c41f9759ab,
				0xc90aeccd913b72d, 0x34bbc662576af4c, 0xd8c603e3f452af4,
				0xc7ccd33c7ec8840, 0x1dd72b9a940203b, 0x5332de587ef6db7,
				0x921f0a7f394da31, 0x788b7b11db2eb65, 0x8657d7524e65147,
				0x75e1c8d5bfc9a3b, 0x30fa1c4cf4d3b6d, 0x43db33e721dfe80,
				0xd7a699cb891b5d6, 0xb33ad679478ad3e, 0x4847ab80b7a21fa,
				0x99aabdd4c393f0a, 0xa3a7989d84dc62b, 0x86d459c88ebad93,
				0xd9d55537bd0f974, 0x543feeb02e0bd9f, 0x918e8b9e5f54d4d,
				0x37fafcb12037f70, 0x0ed21ba0e71b793, 0xb741c4301534f0b,
				0x4c66b270793f7f9, 0x5609871e35ce1fa, 0x4432dc43bf512ec,
				0x8858a0bf0a8c024, 0x184d0fbcc20130e, 0xce1f9c7ca1852e3,
				0xc0812d8e0e957a7, 0x5b2943c2e5b21d3, 0x8e532357645eaeb,
				0xb5ea9dff9aab02b, 0xe58050315f1308c, 0x4285f91e3fdbfbd,
				0x9826404c7c75a7d, 0x71a5270243bacd8, 0x5bf863318fe3897,
				0xee07f435bb94402, 0x07e5db3cd0a5058, 0x8fabbb695ce4e58,
				0x749b40188817a03, 0x16b02668d56a1e8, 0xab13d13e5bda090,
				0x183c5893ffc193b, 0xe912d72bb7f9e53, 0xa861731333ecb85,
				0xca48bde9146c726},
			plaintext:          hhegobfv.RandomInputV(200, 1096486890805657601),
			ciphertextExpected: []uint64{0x00},
			plainMod:           1096486890805657601,
			modDegree:          65536,
			secLevel:           128,
			matrixSize:         200,
			useBsGs:            true,
			bsgN1:              20,
			bsgN2:              10,
		},
	}

	result := make([]TestCase, len(cases))

	// filters large test cases if disabled
	for i := 0; i < len(cases); i++ {
		if cases[i].testType == PackedUseCaseLarge && !enableLargeTestCases {
			continue
		}
		result = append(result, cases[i])
	}

	return cases
}
