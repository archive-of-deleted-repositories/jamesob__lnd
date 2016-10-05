// Copyright (c) 2016 Bitfury Group Limited
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php

package lnwire

import (
	"bytes"
	"testing"
	"github.com/roasbeef/btcd/wire"
	"reflect"
)


func samplePubKey(b byte) [33]byte {
	var a [33]byte
	for i:=0; i<33; i++ {
		a[i] = b
	}
	return a
}

func sampleOutPoint(b byte) wire.OutPoint {
	var w wire.OutPoint
	for i:=0; i<len(w.Hash); i++ {
		w.Hash[i] = b
	}
	w.Index = uint32(b)
	return w
}

func genNeighborHelloMessage() *NeighborHelloMessage {
	p1 := samplePubKey(1)
	p2 := samplePubKey(2)
	p3 := samplePubKey(3)
	e1 := sampleOutPoint(4)
	e2 := sampleOutPoint(5)

	msg := NeighborHelloMessage{
		Channels: []ChannelOperation{
			{
				NodePubKey1: p1,
				NodePubKey2: p2,
				ChannelId: &e1,
				Capacity: 100000,
				Weight: 1.0,
				Operation: 0,
			},
			{
				NodePubKey1: p2,
				NodePubKey2: p3,
				ChannelId: &e2,
				Capacity: 210000,
				Weight: 2.0,
				Operation: 0,
			},
		},
	}
	return &msg
}

func TestNeighborHelloMessageEncodeDecode(t *testing.T) {
	msg1 := genNeighborHelloMessage()

	b := new(bytes.Buffer)
	err := msg1.Encode(b, 0)
	if err != nil {
		t.Fatalf("Can't encode message ", err)
	}
	msg2 := new(NeighborHelloMessage)
	err = msg2.Decode(b, 0)

	// Assert equality of the two instances.
	if !reflect.DeepEqual(msg1, msg2) {
		t.Fatalf("encode/decode error messages don't match %v vs %v",
			msg1, msg2)
	}
}

func TestNeighborHelloMessageReadWrite(t *testing.T) {
	msg1 := genNeighborHelloMessage()

	b := new(bytes.Buffer)
	_, err := WriteMessage(b, msg1, 0, wire.SimNet)
	if err != nil {
		t.Fatalf("Can't write message %v", err)
	}
	_, msg2, _, err := ReadMessage(b, 0, wire.SimNet)
	if err != nil {
		t.Fatalf("Can't read message %v", err)
	}

	// Assert equality of the two instances.
	if !reflect.DeepEqual(msg1, msg2) {
		t.Fatalf("encode/decode error messages don't match %v vs %v",
			msg1, msg2)
	}
}
