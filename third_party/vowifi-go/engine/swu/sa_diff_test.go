package swu

import (
	"encoding/base64"
	"testing"
)

func TestSADiffWithOldBinary(t *testing.T) {
	b64 := "17R8QrysXKAAAAAAAAAAACEgIggAAAAAAAACPCIAALQCAAAsAQEABAMAAAwBAAAMgA4AgAMAAAgDAAAMAwAACAIAAAUAAAAIBAAADgIAACwCAQAEAwAADAEAAAyADgCAAwAACAMAAAwDAAAIAgAABQAAAAgEAAACAgAALAMBAAQDAAAMAQAADIAOAIADAAAIAwAAAgMAAAgCAAACAAAACAQAAAIAAAAsBAEABAMAAAwBAAAMgA4BAAMAAAgDAAACAwAACAIAAAIAAAAIBAAAAigAAQgADgAAY3YV+te8OJoJqx1xPedbg/zaj+08/WpZk0FCEiSDtQir6uoQgpqVAoAh162osXmC44E+LuPAmBTS4kt35rC4HnVMdu0kyt5LoYiwjSPEHaG9UwenyVATDAYQVvFHmW1Qy4Yo4gh80DlHxAnCZhdlhTAZl0uPM8yaxeP7UMx/JeBXMU7YHbYmzMUWJbozCeGsvBU50uI9jLQs3ICBRvaA3/iVqZ4liRuyLNY8iyQ8+B92Ovbkh60dukc/qX82blzNqBMBB2M5H8enBx3BVOdESf1QtuYNq1Joqpl8IySPpz9i2ftyCjzqiywaYjD7Ip/nCB5iG59Oe+nRSjaPgkbkQSkAACSdMTqxqpv3TI7YzIfGQcAw//5rr9iDisRxF2ALaHbq0ykAABwBAEAEu1IL0zbwzz10QE85K4CtXOsZphMpAAAcAQBABezUm7anc5FlD9zFKaSUVwSBXDDsAAAACAAAQC4="
	old, _ := base64.StdEncoding.DecodeString(b64)
	oldSABody := old[32 : 32+176] // 旧二进制 SA 体 (去掉 4 字节载荷头)

	ourSA := comprehensiveIKEProposal()
	ourBytes, err := ourSA.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal our SA: %v", err)
	}
	t.Logf("OUR SA (%d): %x", len(ourBytes), ourBytes)
	t.Logf("OLD SA body (%d): %x", len(oldSABody), oldSABody)

	if len(ourBytes) != len(oldSABody) {
		t.Fatalf("SA length differs: ours=%d old=%d", len(ourBytes), len(oldSABody))
	}
	diffs := 0
	for i := range ourBytes {
		if ourBytes[i] != oldSABody[i] {
			diffs++
			if diffs <= 10 {
				t.Logf("diff at %d: our=%02x old=%02x", i, ourBytes[i], oldSABody[i])
			}
		}
	}
	if diffs > 0 {
		t.Fatalf("SA differs in %d bytes", diffs)
	}
	t.Logf("SA IDENTICAL! (%d bytes)", len(ourBytes))
}
