package test

import (
	"fmt"
	hhegobfv "github.com/fedejinich/hhego/bfv"
	"github.com/fedejinich/hhego/util"
	"testing"
)

func TestTranscipher1(t *testing.T) {
	pastaSecretKey := []uint64{
		0x07a30, 0x0cfe2, 0x03bbb, 0x06ab7, 0x0de0b, 0x0c36c, 0x01c39, 0x019e0,
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
		0x0d106, 0x0e7fd, 0x04ddf, 0x08bb8, 0x0a3a4, 0x03bcd, 0x036d9, 0x05acf,
	}
	plaintext := []uint64{
		0x0a562, 0x0f020, 0x09ae9, 0x04070, 0x0ad24, 0x044e3, 0x09e05, 0x00f43,
		0x0e8be, 0x0890e, 0x0b1f0, 0x08ccb, 0x0a2e9, 0x0ffe9, 0x0a3b5, 0x02d13,
		0x09740, 0x05c4a, 0x03a94, 0x0a6b8, 0x0b31d, 0x049f2, 0x05b59, 0x01f90,
		0x0f3c2, 0x0948b, 0x0731f, 0x007b7, 0x0c8a7, 0x0b204, 0x02053, 0x0bce5,
		0x01f77, 0x067ee, 0x0d935, 0x09cef, 0x0d72b, 0x0b8e2, 0x07501, 0x0c42f,
		0x04e85, 0x062f0, 0x07742, 0x076c8, 0x08f22, 0x01d4f, 0x0bec7, 0x09376,
		0x08969, 0x0dd32, 0x00180, 0x06e3d, 0x0459e, 0x02618, 0x0d37b, 0x06f51,
		0x081de, 0x0428e, 0x08f8e, 0x034de, 0x0089b, 0x00340, 0x04f2a, 0x0a51b,
		0x02b2e, 0x0857e, 0x0de50, 0x0a7eb, 0x0cae8, 0x0287f, 0x0b9e9, 0x0bc45,
		0x0ace7, 0x0d9b8, 0x083bd, 0x0e774, 0x0c4d4, 0x0a5f3, 0x084a5, 0x006b0,
		0x07f49, 0x04e5d, 0x0d5c6, 0x0d94f, 0x09dd0, 0x0e6cf, 0x0a4f3, 0x0cb91,
		0x03ec7, 0x039ce, 0x084e7, 0x0cefe, 0x0f57a, 0x04c3d, 0x01e06, 0x05c1f,
		0x044cf, 0x03226, 0x062e1, 0x02310, 0x086f5, 0x0209d, 0x038d2, 0x03d98,
		0x0376f, 0x0f7e3, 0x0f7b3, 0x02eb8, 0x00210, 0x0d1d2, 0x09ea1, 0x002d6,
		0x01c71, 0x01eea, 0x007b1, 0x0df37, 0x0d01d, 0x06f53, 0x0957b, 0x0479e,
		0x0ecb6, 0x08c2a, 0x0e56d, 0x05026, 0x07ec2, 0x09f77, 0x0824b, 0x07295,
	}
	ciphertextExpected := []uint64{
		0x01c4f, 0x0e3e4, 0x08fe2, 0x0d7db, 0x05594, 0x05c72, 0x0962a, 0x02c3c,
		0x0b3dd, 0x07975, 0x0928b, 0x01024, 0x0632e, 0x07702, 0x05ca1, 0x08e2d,
		0x09b4c, 0x00747, 0x0d484, 0x005ad, 0x0674c, 0x07fd1, 0x00a34, 0x036c7,
		0x014dc, 0x08b83, 0x000e7, 0x00097, 0x03f69, 0x03e8b, 0x07d3b, 0x0de0a,
		0x0bfa6, 0x0ac00, 0x0caea, 0x08cb9, 0x0f1c5, 0x0812a, 0x04071, 0x0a573,
		0x0ed1b, 0x0fe51, 0x08be8, 0x030b3, 0x05493, 0x01d44, 0x0869c, 0x09376,
		0x032bb, 0x0ee24, 0x01b04, 0x01631, 0x0b71a, 0x0590c, 0x06418, 0x0fe7f,
		0x07678, 0x003b4, 0x0f9cb, 0x0ae4c, 0x04b63, 0x0dcd2, 0x04224, 0x07849,
		0x0cdf6, 0x0d4ee, 0x0a804, 0x0daf9, 0x09ef8, 0x004d7, 0x0701a, 0x02467,
		0x09a43, 0x00141, 0x0bb40, 0x0734d, 0x00932, 0x00cd4, 0x09052, 0x0d760,
		0x093bf, 0x0ee3f, 0x0d6bb, 0x09261, 0x0b23d, 0x0c35d, 0x0131a, 0x0a773,
		0x08098, 0x041fe, 0x04acb, 0x061b2, 0x034e4, 0x0f36c, 0x0aa38, 0x09144,
		0x00b40, 0x06f83, 0x001c2, 0x095c0, 0x075e4, 0x0ddcd, 0x06d0d, 0x0e9fa,
		0x0aeb9, 0x0d277, 0x02c4b, 0x09d81, 0x0e805, 0x03830, 0x0f452, 0x0266a,
		0x04fc0, 0x0f505, 0x01f14, 0x09eea, 0x081d0, 0x0ca4f, 0x016d5, 0x0f2fb,
		0x0a3ed, 0x03868, 0x09ea1, 0x0c657, 0x0b8e3, 0x05663, 0x07a04, 0x02e7b,
	}
	plainMod := 65537
	modDegree := 16384
	secLevel := 128
	useBsGs := true

	testTranscipher(t, pastaSecretKey, plaintext, ciphertextExpected, uint64(plainMod), uint64(modDegree), uint64(secLevel),
		20, 10, useBsGs)
}

func TestTranscipher2(t *testing.T) {
	pastaSecretKey := []uint64{
		0x02d65ac52, 0x1c6b45d1c, 0x1cb39041d, 0x0a114487b, 0x1bd58169e,
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
		0x0bb77980e,
	}
	plaintext := []uint64{
		0x1a1b65740, 0x046fff878, 0x1a244787c, 0x19b9adc20, 0x1cb4417fa,
		0x079387978, 0x0efaefb7c, 0x189c025af, 0x1424aeb2e, 0x123f02976,
		0x1804ee8ee, 0x12063c49e, 0x029590584, 0x147c72676, 0x18c4253a3,
		0x1867281ad, 0x1df27d086, 0x0342bd954, 0x02457133e, 0x0de1d8873,
		0x11d1889be, 0x1165d19bc, 0x03b1950c2, 0x014d08f4b, 0x10bf9a614,
		0x127cfcedc, 0x02ecda103, 0x01a3058a3, 0x1e137301d, 0x07e390f18,
		0x078da5b0c, 0x0c27721bf, 0x083834220, 0x1970bdce4, 0x0c6a5755b,
		0x04e475346, 0x05f679931, 0x0172d452a, 0x0f1a4dc8e, 0x18775e168,
		0x19d628ccd, 0x064c41045, 0x05bbe6138, 0x0c5b0508b, 0x07bb6d0bf,
		0x00d467d03, 0x0baeb0692, 0x1cca0dbbd, 0x04b8b3e38, 0x0edbc9680,
		0x11295e84b, 0x163e2ce30, 0x170a0529d, 0x052392bb1, 0x08bd4c38b,
		0x05fe81fad, 0x152bdf2c5, 0x19081ab4e, 0x1130d6bdc, 0x094d5a837,
		0x0e194f235, 0x1c5fdc491, 0x09cbb8c36, 0x0296c387d, 0x008fc8573,
		0x0165e6962, 0x1db6be44f, 0x03e71a101, 0x02999adae, 0x101d125fa,
		0x07d13b25d, 0x027efa1e1, 0x110b3fb97, 0x16955552f, 0x0557de56e,
		0x10beda1c7, 0x12889efd5, 0x1387138a8, 0x03a715d2c, 0x1b93bc0b1,
		0x0237732e7, 0x11e1cf7e0, 0x11be7a5f0, 0x12adbfe99, 0x05915288f,
		0x00d403db9, 0x0f076fa5c, 0x11a0f03d6, 0x1dc4678c2, 0x19c030984,
		0x044078e08, 0x159f1bb35, 0x01549e211, 0x0ff01e821, 0x0cee93788,
		0x0e160179d, 0x10637a875, 0x1717f7c02, 0x0c90e4a27, 0x1a8c42d1d,
		0x00faa6c1f, 0x01dc36d0b, 0x1501664bc, 0x07bd5030f, 0x025501367,
		0x1aeabcc6b, 0x0da52bc85, 0x14bf2430e, 0x034c4591f, 0x0867e4e73,
		0x031fa2c1e, 0x1a459e731, 0x1b5b6719e, 0x1c8992b8f, 0x1daf9f2b0,
		0x089d0975f, 0x18ba93711, 0x17953e281, 0x161c66a72, 0x13cee6a6b,
		0x1893dcad2, 0x14800f497, 0x1cda13962, 0x1c8a89771, 0x0c19327b1,
		0x19b36ca83, 0x02a742bdf, 0x14f43dead,
	}
	ciphertextExpected := []uint64{
		0x10ae630f6, 0x1b342593c, 0x1a22703a3, 0x11278da7e, 0x0b485f348,
		0x06a4c80be, 0x1b3884552, 0x0f609df0d, 0x0127dd394, 0x01f442434,
		0x083aa9d7e, 0x1e0a5397c, 0x11ff33a95, 0x0caa10205, 0x0dd55c747,
		0x0ebd5afc5, 0x0fb174004, 0x0d9fa8d9c, 0x03e7d8764, 0x1daffa094,
		0x0205a69d0, 0x10979fab7, 0x13e183f05, 0x164c6b7be, 0x1390b04ea,
		0x1b3417634, 0x1c23aa933, 0x19990c796, 0x1e18854e7, 0x192bef16e,
		0x0252e8c7e, 0x002b1ed1f, 0x1cc287958, 0x11ace733b, 0x0f60c703e,
		0x1ccd9e345, 0x072648d7b, 0x0544078c9, 0x0038482f0, 0x033a15f75,
		0x081495975, 0x01da043c4, 0x09837a1c7, 0x1106811b6, 0x0550eaf46,
		0x070c131fc, 0x0a1530b82, 0x041e14c3a, 0x1430d3547, 0x032e4d137,
		0x1d8ed2d74, 0x0e7a7db13, 0x089d9d53d, 0x00d2f97fb, 0x067a78cb5,
		0x122b28119, 0x034e63d08, 0x127aa0158, 0x1b08da8df, 0x0ec2f386b,
		0x037d0cd43, 0x13660b30b, 0x0dc89360c, 0x12fbaab4a, 0x069792c84,
		0x081933bd2, 0x1ce09ecc2, 0x032e0cf96, 0x119c0bc7f, 0x0332b4138,
		0x14e5ef752, 0x042e54bfc, 0x04773bf81, 0x180aa13bf, 0x02ba0e9fa,
		0x1d3efcaa3, 0x1de2d4876, 0x0fa5cfdcf, 0x1cb0a2e6a, 0x0a29612f9,
		0x06d2b8e9d, 0x1aa14bc16, 0x0896d9a4b, 0x1959b0e0d, 0x0a5b8d75f,
		0x05cdbc7c2, 0x10a4fbedd, 0x02ad71956, 0x17fb76a98, 0x0abf9fd6f,
		0x060e647bd, 0x13688bcf4, 0x025d023a4, 0x180b7747c, 0x0c381aca4,
		0x0893314d7, 0x1a5936d5f, 0x178b8b027, 0x19526a837, 0x0d2cbd140,
		0x05ba43672, 0x0abc51e47, 0x0403b248b, 0x14436893d, 0x0386e312a,
		0x0a4abcb30, 0x1a126867e, 0x13218a95f, 0x037e79cb0, 0x0526a9e21,
		0x116e88901, 0x073056820, 0x1acd0f21b, 0x045ebb687, 0x120202ea2,
		0x1b2bb4a5b, 0x180b50bf1, 0x06fda5911, 0x18c2cc9b1, 0x046cde940,
		0x05bd57ced, 0x1694e381d, 0x04e5da0c6, 0x0681d0549, 0x03037bb4d,
		0x00e62d01a, 0x14fb2137e, 0x0a9c2c126,
	}
	plainMod := 8088322049
	modDegree := 32768
	secLevel := 128
	useBsGs := true

	testTranscipher(t, pastaSecretKey, plaintext, ciphertextExpected, uint64(plainMod), uint64(modDegree), uint64(secLevel),
		20, 10, useBsGs)
}

func TestTranscipher3(t *testing.T) {
	pastaSecretKey := []uint64{
		0x892f9ff42160c81, 0xa652a61d10eabf3, 0x76bb71c0ddc0c06,
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
		0xca48bde9146c726,
	}
	plaintext := []uint64{
		0xc38bc593b684d35, 0xa56b31c9bad5eb8, 0x8510b47f0eb5ec8,
		0x68772a2aaa6cec1, 0xf0f8a3f70be3430, 0xcd3c585462e9cfc,
		0x876445b524c763d, 0xa6985641dda19a6, 0x3cfd54942ff5f5a,
		0xbe0d12a915ddd5d, 0x79185296ca754c5, 0x517005c87c9a04e,
		0xaaa7745f5bbd997, 0x894db582d7da82c, 0x6ce761174395285,
		0x53aaa5ec49df996, 0x2e2e0a534baa6a2, 0x097296a87914245,
		0x69ef1897ec4a5e6, 0x18f4bb4f08293ab, 0x4972ee2e27445fd,
		0x74394166d023461, 0xacd7b1a3a03f23d, 0xe3a7cdeb2112595,
		0x15d89fa9165f252, 0x9d7144d9578e1a3, 0x3728bd1aa0a916b,
		0x783db8e61fce4d8, 0x81b235e9479822e, 0x73abbabd11b306b,
		0x2c3099b86f43fbe, 0x347e1671c39dfeb, 0x31f7bb1fef2ca93,
		0xf187ac20166412e, 0x55729b37ad324a5, 0x9c14707743be1f9,
		0x7ee30ed6d43e89e, 0x414c3b5b57b865f, 0x2107fb48e16b5bb,
		0xc4c27ecba72788b, 0x16b83f50aaf4290, 0x464e34b59661a60,
		0x4001a67559ec2c1, 0xd29d27711dfa4d6, 0xc344f87f0144d12,
		0xbd4599dd0f8dad8, 0xab630f47b65b149, 0x58e533048ec6f94,
		0x8f25a15f55baebb, 0x81284e7abc64f1e, 0x12d2855b3bd4c52,
		0x28ac19761028811, 0x493e3c14ff58b73, 0xe615bf47496715e,
		0xc1625ac5176e294, 0x5f5730a87f063ff, 0x6b65eb26849e08e,
		0x0991f1e78e26d7e, 0x32c5c93bb6a4376, 0xe4d0e0f4c864da1,
		0x4a1015794f9960f, 0xbc6c8678e7ca8f5, 0xcdb4cdef5f4a2c1,
		0x2ce1152e715004e, 0x4b06936bb143b99, 0x619478c57bbc228,
		0x305faeb63d11b95, 0xa56d9db6868c59c, 0x3087019f72c2b6f,
		0x695a90a3e231918, 0x09704f0c4977a5b, 0x5adaa61c6ec4d3a,
		0x41b80fb3d614526, 0x24e116c3fc51bda, 0xb749d45e7cc6f94,
		0x30f34b7a9de9320, 0x826793c4866d489, 0x42e4c52ff553c84,
		0x813510c08f9db32, 0x35b8331a3867edf, 0x45648074ac2e007,
		0x7efadfcd2a200bb, 0x94d953ea70765c3, 0x43d65eb2e24b2f8,
		0xf003cfb7b2a6c2a, 0x41aaee89e5ed796, 0x1b9a2391a19b18b,
		0xe6b893c3c1b104c, 0x89396e14a70fceb, 0xd5542dcfd484710,
		0x57e17d19e8e483d, 0x65113cd3e32304b, 0xa3aa5bb9520bc0c,
		0x2a50ed9da3b30fb, 0x313bdef469ebe84, 0x33d18224121b67a,
		0x64cff1458d1440c, 0xce33cca1240b036, 0xdac9f13a9f7e3d0,
		0x0b5b6373ebec9f6, 0x7b2ae21b26a8e20, 0x7bfd480fee0d3dc,
		0x5e68ca77292be74, 0xbf76559ed58fcbb, 0x51fb67fdb1d5d9b,
		0x918fd865859e76c, 0xafa1d643a5896dd, 0xda99f1a31c3739d,
		0x7b7a248f418f9b0, 0x0514777b11591b0, 0xb71dd8ad01b9fbe,
		0x139e7ae3c6eda7d, 0x72698058fe0199e, 0xcf0f4ffd454ca4a,
		0x26b104ceb62a52c, 0x3699726ec380bd4, 0x1032533360acf85,
		0xbc9b55e25506e9b, 0x3255b41ce6cd52d, 0xecda8c310e461c4,
		0x92b4643858efe21, 0x95a127e8c5fd9dd, 0xd7132ff88f46df1,
		0xb775005a72d58b5, 0xdfe047acbd17e0a, 0x8e840ffed351598,
		0x3634981e76cf165, 0x0606dea452c7ac9,
	}
	ciphertextExpected := []uint64{
		0x32a4ba9024be5d4, 0xe8138ae01a5041a, 0xc617ed6a9fda31d,
		0x0b336acb93fa88c, 0x5587b75ea723a0b, 0x511fc73deab089e,
		0x0fa145a9fdecc85, 0x6ccb3a489ad23f7, 0xb81577ff440ef1c,
		0x836920bab807949, 0x57030d916bc954c, 0xd2991852da26e09,
		0x74e90c8e4b0f569, 0x34d421df823ef80, 0x3e73400340edb54,
		0xda15d283f92582f, 0x7c34cbc9f2c86a6, 0x4ae3613b4fa0cc4,
		0x5bfbed459f244f9, 0x842f8621a8460c4, 0x4ed83d377019db6,
		0xd0bd59759b3c3e1, 0x7e633bfd742f1f3, 0x16ae4b432ca26b5,
		0x508f122cc88d763, 0x5913843ce3889c2, 0x0a7d9cb8cafa457,
		0x89f9a5e9b2feab0, 0x5faaf0e6c7b9cb1, 0xb230791bd85252a,
		0xbca07b944f2950c, 0xab80da122955d86, 0x7f10f5ab247bd5b,
		0x5c4d63537a0dc79, 0xef1372d65c5156d, 0x6c6d42d99740421,
		0xc8b6a9084fed32d, 0x34d643219d5bc54, 0x8804b5b6581df5d,
		0x9f92300a91acf18, 0xae1d6ac5a5f556d, 0xf1d51b0916c9551,
		0x93b0d5c3cc0acca, 0x8ffdd4db21d9bc7, 0x061593bb8a570a8,
		0xe4a22b91a4b375c, 0x05385a940684706, 0x502cfc1b2bf00fe,
		0xc175ce4cbbce36a, 0x186f506bf6f4994, 0xc8e1db2a936558b,
		0xda6e3beaf47d43f, 0xec482dab5aed4db, 0x55505a6a51dac79,
		0xb88bfbe201e8498, 0xca78662bba5a059, 0xe9a249532c03619,
		0x13eb9b5da4c710d, 0xa75e4f14ee3444a, 0xc1778e19976b620,
		0xceda86a4697ffb8, 0xcc3c5920463e7c7, 0xd74336f65faf2fd,
		0x08e868886c0ea8c, 0xe6e75d77c3eb771, 0x651204d9d02bf38,
		0x11a1542231ebc2c, 0x41938f76f173246, 0x0fa5f8e8d5d6c50,
		0x855bf44b3a40518, 0x5b8874b8517049f, 0xdba039522b2874e,
		0x59006871ea9eb00, 0x1cecc60af64f6fd, 0x8a62b1c5eaff5e0,
		0xa736defba2bf250, 0xbfbb8b1269d9faa, 0x7b3227bfab76db1,
		0x0d3349a6d2aa665, 0x90fcd6fcb2c4146, 0x26c705938d2db69,
		0x24ecd37c6154a5b, 0xb2839b15765e415, 0x96fdde390dca612,
		0x1bdc67922581bb2, 0xb160bf0b142d087, 0x404581e40316064,
		0x58e0e6cd702e827, 0x46594362be384d3, 0x1c9ebe980ad1ded,
		0x000077e8020a5c7, 0x2c6c25abcd410b3, 0xc31e320f2c4668e,
		0xdfe65c86503e7d4, 0xd0039a43784c5b6, 0x269b1227e23ad1c,
		0x64152a61dd8153b, 0x58f828dee04f4c2, 0x434e4b422303040,
		0x71a093c580da59e, 0xdfb317ef52d31ec, 0x0825d4247c6ebe1,
		0xb40a06c49c41969, 0x956c712cfa990d1, 0xd8c4e18b212fa10,
		0x8d2e7e701a6c185, 0xb9a55502bf11dd4, 0x0a4dc72aea1ea8d,
		0x339b2e2fa933d82, 0x4a350db8cc1c790, 0xd76c24d1aa44ac4,
		0xaa83e0c2682283c, 0x9749722312fd43d, 0x775b0424b8f8328,
		0x4eb6020847b0cf2, 0xc641e2d2ea4750e, 0xb2ccb675faa7c27,
		0x160578697a7d6cd, 0x7be727555955811, 0x020a3d07d72fcef,
		0x67c135a705149d6, 0xbc03ce9d44f2d31, 0x51742c8d86c3cee,
		0x93a094470657f49, 0xa9ca9d8f6ac5f16, 0x2f70c474061158d,
		0x4070a4bf3a6f7e8, 0xb96c6f87591abae,
	}
	plainMod := 1096486890805657601
	modDegree := 65536
	secLevel := 128
	useBsGs := true

	testTranscipher(t, pastaSecretKey, plaintext, ciphertextExpected, uint64(plainMod), uint64(modDegree), uint64(secLevel),
		20, 10, useBsGs)
}

func testTranscipher(t *testing.T, pastaSecretKey, plaintext, ciphertextExpected []uint64, plainMod, modDegree, secLevel,
	bsgN1, bsgN2 uint64, useBsGs bool) {
	matrixSize := uint64(len(plaintext))

	if matrixSize != uint64(len(ciphertextExpected)) {
		t.Errorf("matrix size must be same size of the provided ciphertext ")
	}

	// create bfv cipher
	bfvPastaParams := hhegobfv.PastaParams{
		PastaRounds:         int(PastaParams.Rounds),
		PastaCiphertextSize: int(PastaParams.CiphertextSize),
		Modulus:             int(plainMod),
	}
	bfv := hhegobfv.NewBFVPasta(bfvPastaParams, modDegree, secLevel, matrixSize, bsgN1, bsgN2, useBsGs, plainMod)

	// homomorphically encrypt secret key
	pastaSKCiphertext := bfv.EncryptPastaSecretKey(pastaSecretKey)

	// move from PASTA ciphertext to BFV ciphertext
	bfvCiphertext := bfv.Transcipher(ciphertextExpected, pastaSKCiphertext, useBsGs)

	// final decrypt
	decrypted := bfv.DecryptResult(&bfvCiphertext)
	if !util.EqualSlices(decrypted, plaintext) {
		t.Errorf("decrypted a different vector")
		fmt.Printf("matrixSize = %d\n", matrixSize)
		fmt.Printf("plainMod = %d\n", plainMod)
		fmt.Printf("secLevel = %d\n", secLevel)
	}
}
