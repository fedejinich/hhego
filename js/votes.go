package main

import (
	// "encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"time"

	bfv2 "github.com/fedejinich/hhego/bfv"
	"github.com/fedejinich/hhego/pasta"
	"github.com/tuneinsight/lattigo/v4/bfv"
	"github.com/tuneinsight/lattigo/v4/rlwe"
)

// const VOTE_COUNT = 5
const VOTE_COUNT = 100

type VotesJSON struct {
	Votes [][]uint64 `json:"votes"`
	// VotesBfv   [][]byte   `json:"votesBfv"`
	VotesPasta [][]uint64 `json:"votesPasta"`
	// VotesBfvString []string   `json:"votesBfvString"`
	PastaSK []byte `json:"pastaSK"`
	Rk      []byte `json:"rk"`
	BfvSK   []byte `json:"bfvSK"`
}

func main() {
	pastaSK := []uint64{
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
	bfvParams, _ := bfv.NewParametersFromLiteral(bfv.PN15QP827pq)

	bfvSK, _ := rlwe.NewKeyGenerator(bfvParams.Parameters).
		GenKeyPairNew()
	//_, _ = bfvSK.MarshalBinary()

	pastaParams := pasta.Params{
		SecretKeySize:  pasta.SecretKeySize,
		PlaintextSize:  pasta.PlaintextSize,
		CiphertextSize: pasta.CiphertextSize,
		Rounds:         pasta.Rounds,
	}
	mod := bfvParams.T()
	pastaCipher := pasta.NewPasta(pastaSK, mod, pastaParams)

	rlk := rlwe.NewKeyGenerator(bfvParams.Parameters).
		GenRelinearizationKeyNew(bfvSK)

	// new bfv cipher
	voteLen := uint64(4)
	encryptor, _, _, encoder, _, _ := bfv2.NewBFVPasta(uint64(bfvParams.N()),
		pasta.DefaultSecLevel, voteLen, 20, 10, mod, bfvSK, rlk)

	votes := make([][]uint64, VOTE_COUNT)
	// votesBfv := make([][]byte, VOTE_COUNT)
	votesPasta := make([][]uint64, VOTE_COUNT)
	for i := 0; i < VOTE_COUNT; i++ {
		vot := randomVote()
		v, _, vPasta := generateVote(vot, encryptor, pastaCipher, bfvParams)
		fmt.Printf("%d. v %d + vPasta %d\n", i, v, vPasta)

		votes[i] = v
		// votesBfv = append(votesBfv, vBfv)
		votesPasta[i] = vPasta
	}

	// encrypt ops with pasta
	// vote1, vote1Bfv, vote1Pasta, _ := generateVote([]uint64{0, 1, 0, 0}, encryptor, pastaCipher, bfvParams)
	// fmt.Printf("vote1 %d + vote1Pasta %d\n", vote1, vote1Pasta)
	// vote2, vote2Bfv, vote2Pasta, _ := generateVote([]uint64{0, 1, 0, 0}, encryptor, pastaCipher, bfvParams)
	// fmt.Printf("vote2 %d + vote2Pasta %d\n", vote2, vote2Pasta)
	// vote3, vote3Bfv, vote3Pasta, _ := generateVote([]uint64{0, 0, 1, 0}, encryptor, pastaCipher, bfvParams)
	// fmt.Printf("vote3 %d + vote3Pasta %d\n", vote3, vote3Pasta)
	// vote4, vote4Bfv, vote4Pasta, _ := generateVote([]uint64{0, 1, 0, 0}, encryptor, pastaCipher, bfvParams)
	// fmt.Printf("vote4 %d + vote4Pasta %d\n", vote4, vote4Pasta)
	// vote5, vote5Bfv, vote5Pasta, _ := generateVote([]uint64{0, 0, 0, 1}, encryptor, pastaCipher, bfvParams)
	// fmt.Printf("vote5 %d + vote5Pasta %d\n", vote5, vote5Pasta)

	// votesBfv := [][]byte{vote1Bfv, vote2Bfv, vote3Bfv, vote4Bfv, vote5Bfv}
	// votesPasta := [][]uint64{vote1Pasta, vote2Pasta, vote3Pasta, vote4Pasta, vote5Pasta}
	// votes := [][]uint64{vote1, vote2, vote3, vote4, vote5}

	// BFV encrypt PASTA secret key
	pastaSKCt := bfv2.EncryptPastaSecretKey(pastaSK, encoder, encryptor, bfvParams)
	pastaSKCtBytes, _ := pastaSKCt.MarshalBinary()

	// relin key bytes
	rlkBytes, _ := rlk.MarshalBinary()

	// bfvSK bytes
	bfvSKBytes, _ := bfvSK.MarshalBinary()

	// votesJson := VotesJSON{votes, votesBfv, votesPasta,
	// 	pastaSKCtBytes, rlkBytes, bfvSKBytes}

	votesJson := VotesJSON{votes, votesPasta, pastaSKCtBytes, rlkBytes, bfvSKBytes}

	// todo(fedejinich) this is duplicated code
	// write as .json
	// Write to a file
	err := ioutil.WriteFile("votes.json", toJSON(votesJson), 0644)
	if err != nil {
		panic("couldn't write to file")
	}
}

func toJSON(c interface{}) []byte {
	jsonData, err := json.Marshal(c)
	if err != nil {
		panic("wrong json produced")
	}
	return jsonData
}

func generateVote(vote []uint64, bfvCipher rlwe.Encryptor, pastaCipher pasta.Pasta,
	params bfv.Parameters) ([]uint64, []byte, []uint64) {

	votePasta := pastaCipher.Encrypt(vote)
	vote1Pt := rlwe.NewPlaintext(params.Parameters, params.MaxLevel())
	voteBfv := bfvCipher.EncryptNew(vote1Pt)
	voteBfvBytes, _ := voteBfv.MarshalBinary()

	return vote, voteBfvBytes, votePasta
}

func randomVote() []uint64 {
	rand.Seed(time.Now().UnixNano())
	randomNumber := rand.Intn(11)

	var v []uint64
	switch randomNumber {
	case 0, 1, 2, 3:
		{
			v = []uint64{0, 1, 0, 0}
		}
	case 4, 5, 6:
		{
			v = []uint64{0, 0, 1, 0}
		}
	case 7, 8, 9:
		{
			v = []uint64{0, 0, 0, 1}
		}
	case 10:
		{
			v = []uint64{1, 0, 0, 0}
		}
	default:
		panic("shouldnt happen")
	}

	return v
}

// func tonsOfVotes(v [][]uint64, encryptor rlwe.Encryptor, pastaCipher pasta.Pasta, bfvParams bfv.Parameters) [][]uint64 {
// 	for i := 0; i < 100; i++ {
// 		rand.Seed(time.Now().UnixNano())
// 		randomNumber := rand.Intn(11)
//
// 		switch randomNumber {
// 		case 0, 1, 2, 3:
// 			{
// 				v = append(v, generateVote([]uint64{0, 1, 0, 0}, encryptor, pastaCipher, bfvParams))
// 			}
// 		case 4, 5, 6:
// 			{
// 			}
// 		case 7, 8, 9, 10:
// 			{
// 			}
// 		}
// 	}
//
// 	return v
// }
