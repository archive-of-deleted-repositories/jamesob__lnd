package shachain

import (
	"bytes"
	"testing"

	"github.com/roasbeef/btcd/chaincfg/chainhash"
)

type testInsert struct {
	index      index
	secret     string
	successful bool
}

// tests encodes the test vectors specified in BOLT-03, Appendix D,
// Storage Tests.
var tests = []struct {
	name    string
	inserts []testInsert
}{
	{
		name: "insert_secret correct sequence",
		inserts: []testInsert{
			{
				index: 281474976710655,
				secret: "***REMOVED***" +
					"e6e8db3be6854c475621e007a5dc",
				successful: true,
			},
			{
				index: 281474976710654,
				secret: "***REMOVED***" +
					"a8b4b5bec0c4b872abeba4cb8964",
				successful: true,
			},
			{
				index: 281474976710653,
				secret: "***REMOVED***" +
					"cbf9cd7c043a7d6456b7fc275ad8",
				successful: true,
			},
			{
				index: 281474976710652,
				secret: "27cddaa5624534cb6cb9d7da077cf2b22ab2" +
					"1e9b506fd4998a51d54502e99116",
				successful: true,
			},
			{
				index: 281474976710651,
				secret: "c65716add7aa98ba7acb236352d665cab173" +
					"45fe45b55fb879ff80e6bd0c41dd",
				successful: true,
			},
			{
				index: 281474976710650,
				secret: "***REMOVED***96" +
					"2d03db1574df5a8a5a47e19ce3f2",
				successful: true,
			},
			{
				index: 281474976710649,
				secret: "***REMOVED***59" +
					"fc614298e50a33e331980a220f32",
				successful: true,
			},
			{
				index: 281474976710648,
				secret: "***REMOVED***9b" +
					"31447732e3802e1f7ac44b650e17",
				successful: true,
			},
		},
	},
	{
		name: "insert_secret #1 incorrect",
		inserts: []testInsert{
			{
				index: 281474976710655,
				secret: "***REMOVED***" +
					"e6d28c10301f8f7c4073d5e42e3148",
				successful: true,
			},
			{
				index: 281474976710654,
				secret: "***REMOVED***" +
					"c1a8b4b5bec0c4b872abeba4cb8964",
				successful: false,
			},
		},
	},
	{
		name: "insert_secret #2 incorrect (#1 derived from incorrect)",
		inserts: []testInsert{
			{
				index: 281474976710655,
				secret: "***REMOVED***e6" +
					"d28c10301f8f7c4073d5e42e3148",
				successful: true,
			},
			{
				index: 281474976710654,
				secret: "dddc3a8d14fddf2b68fa8c7fbad274827493" +
					"7479dd0f8930d5ebb4ab6bd866a3",
				successful: true,
			},
			{
				index: 281474976710653,
				secret: "***REMOVED***" +
					"cbf9cd7c043a7d6456b7fc275ad8",
				successful: true,
			},
			{
				index: 281474976710652,
				secret: "27cddaa5624534cb6cb9d7da077cf2b22a" +
					"b21e9b506fd4998a51d54502e99116",
				successful: false,
			},
		},
	},
	{
		name: "insert_secret #3 incorrect",
		inserts: []testInsert{
			{
				index: 281474976710655,
				secret: "***REMOVED***" +
					"e6e8db3be6854c475621e007a5dc",
				successful: true,
			},
			{
				index: 281474976710654,
				secret: "***REMOVED***" +
					"a8b4b5bec0c4b872abeba4cb8964",
				successful: true,
			},
			{
				index: 281474976710653,
				secret: "***REMOVED***" +
					"7d5760b46e9477dae59e87ed423a",
				successful: true,
			},
			{
				index: 281474976710652,
				secret: "27cddaa5624534cb6cb9d7da077cf2b22ab2" +
					"1e9b506fd4998a51d54502e99116",
				successful: false,
			},
		},
	},
	{
		name: "insert_secret #4 incorrect (1,2,3 derived from incorrect)",
		inserts: []testInsert{
			{
				index: 281474976710655,
				secret: "***REMOVED***e6" +
					"d28c10301f8f7c4073d5e42e3148",
				successful: true,
			},
			{
				index: 281474976710654,
				secret: "dddc3a8d14fddf2b68fa8c7fbad274827493" +
					"7479dd0f8930d5ebb4ab6bd866a3",
				successful: true,
			},
			{
				index: 281474976710653,
				secret: "***REMOVED***" +
					"0b7d5760b46e9477dae59e87ed423a",
				successful: true,
			},
			{
				index: 281474976710652,
				secret: "***REMOVED***" +
					"4f8f138d78a7011669c79b37b936f4",
				successful: true,
			},
			{
				index: 281474976710651,
				secret: "c65716add7aa98ba7acb236352d665cab1" +
					"7345fe45b55fb879ff80e6bd0c41dd",
				successful: true,
			},
			{
				index: 281474976710650,
				secret: "***REMOVED***" +
					"962d03db1574df5a8a5a47e19ce3f2",
				successful: true,
			},
			{
				index: 281474976710649,
				secret: "***REMOVED***" +
					"59fc614298e50a33e331980a220f32",
				successful: true,
			},
			{
				index: 281474976710649,
				secret: "***REMOVED***9b" +
					"31447732e3802e1f7ac44b650e17",
				successful: false,
			},
		},
	},
	{
		name: "insert_secret #5 incorrect",
		inserts: []testInsert{
			{
				index: 281474976710655,
				secret: "***REMOVED***" +
					"e6e8db3be6854c475621e007a5dc",
				successful: true,
			},
			{
				index: 281474976710654,
				secret: "***REMOVED***a" +
					"8b4b5bec0c4b872abeba4cb8964",
				successful: true,
			},
			{
				index: 281474976710653,
				secret: "***REMOVED***" +
					"cbf9cd7c043a7d6456b7fc275ad8",
				successful: true,
			},
			{
				index: 281474976710652,
				secret: "***REMOVED***" +
					"e9b506fd4998a51d54502e99116",
				successful: true,
			},
			{
				index: 281474976710651,
				secret: "***REMOVED***" +
					"edd24320d2fcd68e3cc47e2ff6a6",
				successful: true,
			},
			{
				index: 281474976710650,
				secret: "***REMOVED***96" +
					"2d03db1574df5a8a5a47e19ce3f2",
				successful: false,
			},
		},
	},
	{
		name: "insert_secret #6 incorrect (5 derived from incorrect)",
		inserts: []testInsert{
			{
				index: 281474976710655,
				secret: "***REMOVED***" +
					"e6e8db3be6854c475621e007a5dc",
				successful: true,
			},
			{
				index: 281474976710654,
				secret: "***REMOVED***a" +
					"8b4b5bec0c4b872abeba4cb8964",
				successful: true,
			},
			{
				index: 281474976710653,
				secret: "***REMOVED***" +
					"cbf9cd7c043a7d6456b7fc275ad8",
				successful: true,
			},
			{
				index: 281474976710652,
				secret: "***REMOVED***" +
					"e9b506fd4998a51d54502e99116",
				successful: true,
			},
			{
				index: 281474976710651,
				secret: "***REMOVED***" +
					"edd24320d2fcd68e3cc47e2ff6a6",
				successful: true,
			},
			{
				index: 281474976710650,
				secret: "b7e76a83668bde38b373970155c868a65330" +
					"4308f9896692f904a23731224bb1",
				successful: true,
			},
			{
				index: 281474976710649,
				secret: "***REMOVED***59f" +
					"c614298e50a33e331980a220f32",
				successful: true,
			},
			{
				index: 281474976710648,
				secret: "***REMOVED***9b" +
					"31447732e3802e1f7ac44b650e17",
				successful: false,
			},
		},
	},
	{
		name: "insert_secret #7 incorrect",
		inserts: []testInsert{
			{
				index: 281474976710655,
				secret: "***REMOVED***" +
					"e6e8db3be6854c475621e007a5dc",
				successful: true,
			},
			{
				index: 281474976710654,
				secret: "***REMOVED***a" +
					"8b4b5bec0c4b872abeba4cb8964",
				successful: true,
			},
			{
				index: 281474976710653,
				secret: "***REMOVED***" +
					"cbf9cd7c043a7d6456b7fc275ad8",
				successful: true,
			},
			{
				index: 281474976710652,
				secret: "***REMOVED***" +
					"e9b506fd4998a51d54502e99116",
				successful: true,
			},
			{
				index: 281474976710651,
				secret: "c65716add7aa98ba7acb236352d665cab173" +
					"45fe45b55fb879ff80e6bd0c41dd",
				successful: true,
			},
			{
				index: 281474976710650,
				secret: "***REMOVED***96" +
					"2d03db1574df5a8a5a47e19ce3f2",
				successful: true,
			},
			{
				index: 281474976710649,
				secret: "***REMOVED***" +
					"ca9e326f3a96e7194fe8ea8af6c0a3",
				successful: true,
			},
			{
				index: 281474976710648,
				secret: "***REMOVED***" +
					"9b31447732e3802e1f7ac44b650e17",
				successful: false,
			},
		},
	},
	{
		name: "insert_secret #8 incorrect",
		inserts: []testInsert{
			{
				index: 281474976710655,
				secret: "***REMOVED***" +
					"e6e8db3be6854c475621e007a5dc",
				successful: true,
			},
			{
				index: 281474976710654,
				secret: "***REMOVED***a" +
					"8b4b5bec0c4b872abeba4cb8964",
				successful: true,
			},
			{
				index: 281474976710653,
				secret: "***REMOVED***" +
					"cbf9cd7c043a7d6456b7fc275ad8",
				successful: true,
			},
			{
				index: 281474976710652,
				secret: "***REMOVED***" +
					"e9b506fd4998a51d54502e99116",
				successful: true,
			},
			{
				index: 281474976710651,
				secret: "c65716add7aa98ba7acb236352d665cab173" +
					"45fe45b55fb879ff80e6bd0c41dd",
				successful: true,
			},
			{
				index: 281474976710650,
				secret: "***REMOVED***96" +
					"2d03db1574df5a8a5a47e19ce3f2",
				successful: true,
			},
			{
				index: 281474976710649,
				secret: "***REMOVED***" +
					"59fc614298e50a33e331980a220f32",
				successful: true,
			},
			{
				index: 281474976710648,
				secret: "***REMOVED***" +
					"a46ca460addc49009bda875ec88fa4",
				successful: false,
			},
		},
	},
}

// TestSpecificationShaChainInsert is used to check the consistency with
// specification hash insert function.
func TestSpecificationShaChainInsert(t *testing.T) {
	t.Parallel()

	for _, test := range tests {
		receiver := NewRevocationStore()

		for _, insert := range test.inserts {
			secret, err := hashFromString(insert.secret)
			if err != nil {
				t.Fatal(err)
			}

			if err := receiver.AddNextEntry(secret); err != nil {
				if insert.successful {
					t.Fatalf("Failed (%v): error was "+
						"received but it shouldn't: "+
						"%v", test.name, err)
				}
			} else {
				if !insert.successful {
					t.Fatalf("Failed (%v): error wasn't "+
						"received", test.name)
				}
			}
		}

		t.Logf("Passed (%v)", test.name)
	}
}

// TestShaChainStore checks the ability of shachain store to hold the produced
// secrets after recovering from bytes data.
func TestShaChainStore(t *testing.T) {
	t.Parallel()

	seed := chainhash.DoubleHashH([]byte("shachaintest"))

	sender := NewRevocationProducer(seed)
	receiver := NewRevocationStore()

	for n := uint64(0); n < 10000; n++ {
		sha, err := sender.AtIndex(n)
		if err != nil {
			t.Fatal(err)
		}

		if err = receiver.AddNextEntry(sha); err != nil {
			t.Fatal(err)
		}
	}

	var b bytes.Buffer
	if err := receiver.Encode(&b); err != nil {
		t.Fatal(err)
	}

	newReceiver, err := NewRevocationStoreFromBytes(&b)
	if err != nil {
		t.Fatal(err)
	}

	for n := uint64(0); n < 10000; n++ {
		if _, err := newReceiver.LookUp(n); err != nil {
			t.Fatal(err)
		}
	}
}
