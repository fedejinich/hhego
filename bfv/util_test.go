package bfv

import (
	"hhego/pasta"
	"hhego/util"
	"math"
	"testing"
)

type UtilTestCase struct {
	modulus   uint64
	bfvDegree uint64
}

func (u *UtilTestCase) Halfslots() int {
	return int(u.bfvDegree / 2)
}

var BfvHalfSlots = int(math.Pow(2, 15) / 2) // todo(fedejinich) this is ugly, do it better

func TestUtil(t *testing.T) {
	testCases := []UtilTestCase{
		{modulus: 65537, bfvDegree: uint64(math.Pow(2, 15))},
		{modulus: 8088322049, bfvDegree: uint64(math.Pow(2, 15))},
		//{modulus: 1096486890805657601, bfvDegree: uint64(math.Pow(2,16))},
	}

	for _, tc := range testCases {
		t.Run("TestUtil_MatMulDiagonal", func(t *testing.T) {
			pastaUtil, pastaParams := newPastaUtil(tc.modulus)
			pastaUtil.InitShake(uint64(123456789), 0)

			bfv, _ := NewBFVBasic(pastaParams, tc.modulus, tc.bfvDegree)

			s1 := testVec()
			s2 := testVec2()

			// split the state to the second half of the slots
			pLength := tc.Halfslots() + len(s1)
			p := make([]uint64, pLength)
			for i := 0; i < pasta.T; i++ {
				p[i] = s1[i]
				p[i+tc.Halfslots()] = s2[i]
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
			ct = Matmul(ct, mat1, mat2, uint64(tc.Halfslots()*2),
				uint64(tc.Halfslots()), bfv.Evaluator, bfv.Encoder, bfv.Params)

			state1 := bfv.DecryptPacked(ct, uint64(len(s1)))
			if !util.EqualSlices(state1, toVec(s1)) { // assert for the 1st pasta branch
				t.Errorf("bfv Matmul is not the same as pasta Matmul")
			}

			state2 := bfv.DecryptPacked(ct, uint64(tc.Halfslots()+pasta.T))[tc.Halfslots():]
			if !util.EqualSlices(state2, toVec(s2)) { // assert for the 2nd pasta branch
				t.Errorf("bfv Matmul is not the same as pasta Matmul")
			}
		})

		t.Run("TestUtil_AddRc", func(t *testing.T) {
			pastaUtil, pastaParams := newPastaUtil(tc.modulus)
			bfv, _ := NewBFVBasic(pastaParams, tc.modulus, tc.bfvDegree)

			s1 := testVec()
			s2 := testVec2()

			// split the state to the second half of the slots
			pLength := tc.Halfslots() + len(s1)
			p := make([]uint64, pLength)
			for i := 0; i < pasta.T; i++ {
				p[i] = s1[i]
				p[i+tc.Halfslots()] = s2[i]
			}

			pt := bfv.Encoder.EncodeNew(p, bfv.Params.MaxLevel())
			ct := bfv.Encrypt(pt)

			pastaUtil.InitShake(uint64(123456789), 0)
			rcVec := pastaUtil.RCVec(uint64(tc.Halfslots()))

			// test AddRc
			ct = AddRc(ct, rcVec, bfv.Encoder, bfv.Evaluator, bfv.Params)
			pastaUtil.AddRcBy(s1, rcVec)
			pastaUtil.AddRcBy(s2, rcVec[tc.Halfslots():])

			decrypted := bfv.DecryptPacked(ct, uint64(len(s1)))
			if !util.EqualSlices(decrypted, toVec(s1)) {
				t.Errorf("bfv AddRc is not the same as pasta AddRc")
			}

			decrypted2 := bfv.DecryptPacked(ct, uint64(tc.Halfslots()+pasta.T))
			decrypted2 = decrypted2[tc.Halfslots():]
			if !util.EqualSlices(decrypted2, toVec(s2)) {
				t.Errorf("bfv AddRc is not the same as pasta AddRc")
			}
		})

		t.Run("TestUtil_Mix", func(t *testing.T) {
			pastaUtil, pastaParams := newPastaUtil(tc.modulus)
			bfv, _ := NewBFVBasic(pastaParams, tc.modulus, tc.bfvDegree)

			s1 := testVec()
			s2 := testVec2()

			// split the state to the second half of the slots
			pLength := tc.Halfslots() + len(s1)
			p := make([]uint64, pLength)
			for i := 0; i < pasta.T; i++ {
				p[i] = s1[i]
				p[i+tc.Halfslots()] = s2[i]
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
			bfv, _ := NewBFVBasic(pastaParams, tc.modulus, tc.bfvDegree)

			s1 := testVec()
			s2 := testVec2()

			// split the state to the second half of the slots
			pLength := tc.Halfslots() + len(s1)
			p := make([]uint64, pLength)
			for i := 0; i < pasta.T; i++ {
				p[i] = s1[i]
				p[i+tc.Halfslots()] = s2[i]
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

			decrypted2 := bfv.DecryptPacked(ct, uint64(tc.Halfslots()+pasta.T))
			decrypted2 = decrypted2[tc.Halfslots():]
			if !util.EqualSlices(decrypted2, toVec(s2)) {
				t.Errorf("bfv SCube is not the same as pasta SCube")
			}
		})

		t.Run("TestUtil_SboxFeistel", func(t *testing.T) {
			pastaUtil, pastaParams := newPastaUtil(tc.modulus)
			pastaUtil2, _ := newPastaUtil(tc.modulus)
			bfv, _ := NewBFVBasic(pastaParams, tc.modulus, tc.bfvDegree)

			s1 := testVec()
			s2 := testVec2()

			// split the state to the second half of the slots
			pLength := tc.Halfslots() + len(s1)
			p := make([]uint64, pLength)
			for i := 0; i < pasta.T; i++ {
				p[i] = s1[i]
				p[i+tc.Halfslots()] = s2[i]
			}

			pt := bfv.Encoder.EncodeNew(p, bfv.Params.MaxLevel())
			ct := bfv.Encrypt(pt)

			// test SboxCube
			ct = SboxFeistel(ct, uint64(tc.Halfslots()), bfv.Evaluator, bfv.Encoder, bfv.Params)
			pastaUtil.SboxFeistel(s1)
			pastaUtil2.SboxFeistel(s2)

			decrypted := bfv.DecryptPacked(ct, uint64(len(s1)))
			if !util.EqualSlices(decrypted, toVec(s1)) {
				t.Errorf("bfv SFeistel is not the same as pasta SFeistel")
			}

			decrypted2 := bfv.DecryptPacked(ct, uint64(tc.Halfslots()+pasta.T))
			decrypted2 = decrypted2[tc.Halfslots():]
			if !util.EqualSlices(decrypted2, toVec(s2)) {
				t.Errorf("bfv SFeistel is not the same as pasta SFeistel")
			}
		})

		t.Run("TestUtil_BasicBFVDecrypt", func(t *testing.T) {
			_, pastaParams := newPastaUtil(tc.modulus)
			bfv, _ := NewBFVBasic(pastaParams, tc.modulus, tc.bfvDegree)

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
	return pasta.NewUtil(secretKey(), modulus, rounds), PastaParams{rounds, 128,
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
