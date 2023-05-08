package bfv

import (
	"hhego/pasta"
	"hhego/util"
	"math"
	"testing"
)

var P = pasta.Params{SecretKeySize: pasta.SecretKeySize, PlaintextSize: pasta.PlaintextSize,
	CiphertextSize: pasta.CiphertextSize, Rounds: 3}

type UtilTestCase struct {
	modulus uint64
}

var BfvHalfSlots = int(math.Pow(2, 15) / 2) // todo(fedejinich) this is ugly, do it better

const BfvDegreeTest = 32768

func TestUtil(t *testing.T) {
	testCases := []UtilTestCase{
		{modulus: 65537},
		{modulus: 8088322049},
	}

	for _, tc := range testCases {
		t.Run("TestUtil_MatMulDiagonal", func(t *testing.T) {
			pastaUtil, pastaParams := newPastaUtil(tc.modulus)
			pastaUtil.InitShake(uint64(123456789), 0)

			bfv, _ := NewBFVBasic(pastaParams, tc.modulus, BfvDegreeTest)

			s1 := testVec()
			s2 := testVec2()

			// split the state to the second half of the slots
			pLength := BfvHalfSlots + len(s1)
			p := make([]uint64, pLength)
			for i := 0; i < pasta.T; i++ {
				p[i] = s1[i]
				p[i+BfvHalfSlots] = s2[i]
			}

			pt := bfv.Encoder.EncodeNew(p, bfv.Params.MaxLevel())
			ct := bfv.Encrypt(pt)

			r1 := pastaUtil.GetRandomVector(false)
			r2 := pastaUtil.GetRandomVector(false)
			mat1 := pastaUtil.RandomMatrixBy(r1)
			mat2 := pastaUtil.RandomMatrixBy(r2)

			// test MatMul
			pastaUtil.MatmulBy(s1, r1)
			pastaUtil.MatmulBy(s2, r2)
			ct = Matmul(ct, mat1, mat2, uint64(BfvHalfSlots*2),
				uint64(BfvHalfSlots), bfv.Evaluator, bfv.Encoder, bfv.Params)

			state1 := bfv.DecryptPacked(ct, uint64(len(s1)))
			if !util.EqualSlices(state1, toVec(s1)) { // assert for the 1st pasta branch
				t.Errorf("bfv Matmul is not the same as pasta Matmul")
			}

			state2 := bfv.DecryptPacked(ct, uint64(BfvHalfSlots+pasta.T))[BfvHalfSlots:]
			if !util.EqualSlices(state2, toVec(s2)) { // assert for the 2nd pasta branch
				t.Errorf("bfv Matmul is not the same as pasta Matmul")
			}
		})

		t.Run("TestUtil_AddRc", func(t *testing.T) {
			pastaUtil, pastaParams := newPastaUtil(tc.modulus)
			bfv, _ := NewBFVBasic(pastaParams, tc.modulus, BfvDegreeTest)

			s1 := testVec()
			s2 := testVec2()

			// split the state to the second half of the slots
			pLength := BfvHalfSlots + len(s1)
			p := make([]uint64, pLength)
			for i := 0; i < pasta.T; i++ {
				p[i] = s1[i]
				p[i+BfvHalfSlots] = s2[i]
			}

			pt := bfv.Encoder.EncodeNew(p, bfv.Params.MaxLevel())
			ct := bfv.Encrypt(pt)

			pastaUtil.InitShake(uint64(123456789), 0)
			rcVec := pastaUtil.RCVec(uint64(BfvHalfSlots))

			// test AddRc
			ct = AddRc(ct, rcVec, bfv.Encoder, bfv.Evaluator, bfv.Params)
			pastaUtil.AddRcBy(s1, rcVec)
			pastaUtil.AddRcBy(s2, rcVec[BfvHalfSlots:])

			decrypted := bfv.DecryptPacked(ct, uint64(len(s1)))
			if !util.EqualSlices(decrypted, toVec(s1)) {
				t.Errorf("bfv AddRc is not the same as pasta AddRc")
			}

			decrypted2 := bfv.DecryptPacked(ct, uint64(BfvHalfSlots+pasta.T))
			decrypted2 = decrypted2[BfvHalfSlots:]
			if !util.EqualSlices(decrypted2, toVec(s2)) {
				t.Errorf("bfv AddRc is not the same as pasta AddRc")
			}
		})

		t.Run("TestUtil_Mix", func(t *testing.T) {
			pastaUtil, pastaParams := newPastaUtil(tc.modulus)
			bfv, _ := NewBFVBasic(pastaParams, tc.modulus, BfvDegreeTest)

			s1 := testVec()
			s2 := testVec2()

			// split the state to the second half of the slots
			pLength := BfvHalfSlots + len(s1)
			p := make([]uint64, pLength)
			for i := 0; i < pasta.T; i++ {
				p[i] = s1[i]
				p[i+BfvHalfSlots] = s2[i]
			}

			pt := bfv.Encoder.EncodeNew(p, bfv.Params.MaxLevel()) // todo(fedejinich) this encoding is wrong
			ct := bfv.Encrypt(pt)

			// test Mix
			pastaUtil.MixBy(s1, s2)
			ct = Mix(ct, bfv.Evaluator, bfv.Encoder)

			stateAfterMix := toVec(pastaUtil.State())
			decrypted := bfv.DecryptPacked(ct, uint64(len(s1)))
			if !util.EqualSlices(decrypted, stateAfterMix) {
				t.Errorf("bfv Mix is not the same as pasta Mix")
			}
		})

		t.Run("TestUtil_SboxCube", func(t *testing.T) {
			pastaUtil, pastaParams := newPastaUtil(tc.modulus)
			pastaUtil2, _ := newPastaUtil(tc.modulus)
			bfv, _ := NewBFVBasic(pastaParams, tc.modulus, BfvDegreeTest)

			s1 := testVec()
			s2 := testVec2()

			// split the state to the second half of the slots
			pLength := BfvHalfSlots + len(s1)
			p := make([]uint64, pLength)
			for i := 0; i < pasta.T; i++ {
				p[i] = s1[i]
				p[i+BfvHalfSlots] = s2[i]
			}

			pt := bfv.Encoder.EncodeNew(p, bfv.Params.MaxLevel())
			ct := bfv.Encrypt(pt)

			// test SboxCube
			pastaUtil.SboxCube(s1)
			pastaUtil2.SboxCube(s2)
			ct = SboxCube(ct, bfv.Evaluator)

			decrypted := bfv.DecryptPacked(ct, uint64(len(s1)))
			if !util.EqualSlices(decrypted, toVec(s1)) {
				t.Errorf("bfv SCube is not the same as pasta SCube")
			}

			decrypted2 := bfv.DecryptPacked(ct, uint64(BfvHalfSlots+pasta.T))
			decrypted2 = decrypted2[BfvHalfSlots:]
			if !util.EqualSlices(decrypted2, toVec(s2)) {
				t.Errorf("bfv SCube is not the same as pasta SCube")
			}
		})

		t.Run("TestUtil_SboxFeistel", func(t *testing.T) {
			pastaUtil, pastaParams := newPastaUtil(tc.modulus)
			pastaUtil2, _ := newPastaUtil(tc.modulus)
			bfv, _ := NewBFVBasic(pastaParams, tc.modulus, BfvDegreeTest)

			s1 := testVec()
			s2 := testVec2()

			// split the state to the second half of the slots
			pLength := BfvHalfSlots + len(s1)
			p := make([]uint64, pLength)
			for i := 0; i < pasta.T; i++ {
				p[i] = s1[i]
				p[i+BfvHalfSlots] = s2[i]
			}

			pt := bfv.Encoder.EncodeNew(p, bfv.Params.MaxLevel())
			ct := bfv.Encrypt(pt)

			// test SboxCube
			ct = SboxFeistel(ct, uint64(BfvHalfSlots), bfv.Evaluator, bfv.Encoder, bfv.Params)
			pastaUtil.SboxFeistel(s1)
			pastaUtil2.SboxFeistel(s2)

			decrypted := bfv.DecryptPacked(ct, uint64(len(s1)))
			if !util.EqualSlices(decrypted, toVec(s1)) {
				t.Errorf("bfv SFeistel is not the same as pasta SFeistel")
			}

			decrypted2 := bfv.DecryptPacked(ct, uint64(BfvHalfSlots+pasta.T))
			decrypted2 = decrypted2[BfvHalfSlots:]
			if !util.EqualSlices(decrypted2, toVec(s2)) {
				t.Errorf("bfv SFeistel is not the same as pasta SFeistel")
			}
		})

		t.Run("TestUtil_BasicBFVDecrypt", func(t *testing.T) {
			_, pastaParams := newPastaUtil(tc.modulus)
			bfv, _ := NewBFVBasic(pastaParams, tc.modulus, BfvDegreeTest)

			vec := testVec()

			// basic bfv decrypt
			pt := bfv.Encoder.EncodeNew(toVec(vec), bfv.Params.MaxLevel())
			ct := bfv.Encrypt(pt)
			d := bfv.DecryptPacked(ct, uint64(len(vec)))
			if !util.EqualSlices(d, toVec(vec)) {
				t.Errorf("not equal slices")
			}
		})
	}
}

func testVec() *pasta.Block {
	vecSize := pasta.T
	var v pasta.Block
	for j := 0; j < vecSize; j++ {
		if j == 69 {
			v[j] = 85
		} else if j == 42 {
			v[j] = 58
		} else if j%2 == 0 {
			v[j] = 46
		} else {
			v[j] = 35
		}
	}
	return &v
}

func testVec2() *pasta.Block {
	vecSize := pasta.T
	var v pasta.Block
	for j := 0; j < vecSize; j++ {
		if j == 69 {
			v[j] = 91
		} else if j == 42 {
			v[j] = 17
		} else if j%2 == 0 {
			v[j] = 88
		} else {
			v[j] = 27
		}
	}
	return &v
}

func toVec(b *pasta.Block) []uint64 {
	v := make([]uint64, len(b))
	for i, e := range b {
		v[i] = e
	}

	return v
}

func newPastaUtil(modulus uint64) (pasta.Util, PastaParams) {
	rounds := 3
	return pasta.NewUtil(secretKey2(), modulus, rounds), PastaParams{rounds, 128,
		int(modulus)}
}

func secretKey() []uint64 {
	return []uint64{0x07a30, 0x0cfe2, 0x03bbb, 0x06ab7, 0x0de0b, 0x0c36c, 0x01c39,
		0x019e0, 0x0e09c, 0x04441, 0x0c560, 0x00fd4, 0x0c611, 0x0a3fd,
		0x0d408, 0x01b17, 0x0fa02, 0x054ea, 0x0afeb, 0x0193b, 0x0b6fa,
		0x09e80, 0x0e253, 0x03f49, 0x0c8a5, 0x0c6a4, 0x0badf, 0x0bcfc,
		0x0ecbd, 0x06ccd, 0x04f10, 0x0f1d6, 0x07da9, 0x079bd, 0x08e84,
		0x0b774, 0x07435, 0x09206, 0x086d4, 0x070d4, 0x04383, 0x05d65,
		0x0b015, 0x058fe, 0x0f0d1, 0x0c700, 0x0dc40, 0x02cea, 0x096db,
		0x06c84, 0x008ef, 0x02abc, 0x03fdf, 0x0ddaf, 0x028c7, 0x0ded4,
		0x0bb88, 0x020cd, 0x075c3, 0x0caf7, 0x0a8ff, 0x0eadd, 0x01c02,
		0x083b1, 0x0a439, 0x0e2db, 0x09baa, 0x02c09, 0x0b5ba, 0x0c7f5,
		0x0161c, 0x0e94d, 0x0bf6f, 0x070f1, 0x0f574, 0x0784b, 0x08cdb,
		0x08529, 0x027c9, 0x010bc, 0x079ca, 0x01ff1, 0x0219a, 0x00130,
		0x0ff77, 0x012fb, 0x03ca6, 0x0d27d, 0x05747, 0x0fa91, 0x00766,
		0x04f27, 0x00254, 0x06e8d, 0x0e071, 0x0804e, 0x08b0e, 0x08e59,
		0x04cd8, 0x0485f, 0x0bde0, 0x03082, 0x01225, 0x01b5f, 0x0a83e,
		0x0794a, 0x05104, 0x09c19, 0x0fdcf, 0x036fe, 0x01e41, 0x00038,
		0x086e8, 0x07046, 0x02c07, 0x04953, 0x07869, 0x0e9c1, 0x0af86,
		0x0503a, 0x00f31, 0x0535c, 0x0c2cb, 0x073b9, 0x028e3, 0x03c2b,
		0x0cb90, 0x00c33, 0x08fe7, 0x068d3, 0x09a8c, 0x008e0, 0x09fe8,
		0x0f107, 0x038ec, 0x0b014, 0x007eb, 0x06335, 0x0afcc, 0x0d55c,
		0x0a816, 0x0fa07, 0x05864, 0x0dc8f, 0x07720, 0x0deef, 0x095db,
		0x07cbe, 0x0834e, 0x09adc, 0x0bab8, 0x0f8f7, 0x0b21a, 0x0ca98,
		0x01a6c, 0x07e4a, 0x04545, 0x078a7, 0x0ba53, 0x00040, 0x09bc5,
		0x0bc7a, 0x0401c, 0x00c30, 0x00000, 0x0318d, 0x02e95, 0x065ed,
		0x03749, 0x090b3, 0x01e23, 0x0be04, 0x0b612, 0x08c0c, 0x06ea3,
		0x08489, 0x0a52c, 0x0aded, 0x0fd13, 0x0bd31, 0x0c225, 0x032f5,
		0x06aac, 0x0a504, 0x0d07e, 0x0bb32, 0x08174, 0x0bd8b, 0x03454,
		0x04075, 0x06803, 0x03df5, 0x091a0, 0x0d481, 0x09f04, 0x05c54,
		0x0d54f, 0x00344, 0x09ffc, 0x00262, 0x01fbf, 0x0461c, 0x01985,
		0x05896, 0x0fedf, 0x097ce, 0x0b38d, 0x0492f, 0x03764, 0x041ad,
		0x02849, 0x0f927, 0x09268, 0x0bafd, 0x05727, 0x033bc, 0x03249,
		0x08921, 0x022da, 0x0b2dc, 0x0e42d, 0x055fa, 0x0a654, 0x073f0,
		0x08df1, 0x08149, 0x00d1b, 0x0ac47, 0x0f304, 0x03634, 0x0168b,
		0x00c59, 0x09f7d, 0x0596c, 0x0d164, 0x0dc49, 0x038ff, 0x0a495,
		0x07d5a, 0x02d4, 0x06c6c, 0x0ea76, 0x09af5, 0x0bea6, 0x08eea,
		0x0fbb6, 0x09e45, 0x0e9db, 0x0d106, 0x0e7fd, 0x04ddf, 0x08bb8,
		0x0a3a4, 0x03bcd, 0x036d9, 0x05acf}
}

func secretKey2() []uint64 {
	return []uint64{0x02d65ac52, 0x1c6b45d1c, 0x1cb39041d, 0x0a114487b, 0x1bd58169e,
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
		0x0bb77980e}
}
