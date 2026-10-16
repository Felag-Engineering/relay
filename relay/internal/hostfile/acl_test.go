package hostfile

import "testing"

func TestParsePOSIXACL_Minimal(t *testing.T) {
	a, err := parsePOSIXACL(acl(2, [3]uint32{tagUserObj, 6, 0}, [3]uint32{tagGroupObj, 4, 0}, [3]uint32{tagOther, 0, 0}))
	if err != nil {
		t.Fatal(err)
	}
	if a.groupObj != 4 || a.mask != 7 || a.effective(a.groupObj) != 4 {
		t.Fatalf("got %+v", a)
	}
}

func TestParsePOSIXACL_WithMask(t *testing.T) {
	a, err := parsePOSIXACL(baseACL(6, 4, [3]uint32{tagUser, 6, 5}, [3]uint32{tagGroup, 6, 7}))
	if err != nil {
		t.Fatal(err)
	}
	if a.effective(a.groupObj) != 4 || len(a.users) != 1 || len(a.groups) != 1 || a.effective(a.users[0].perm) != 4 {
		t.Fatalf("got %+v", a)
	}
}

func TestParsePOSIXACL_Malformed(t *testing.T) {
	ok := baseACL(4, 4)
	cases := map[string][]byte{
		"empty":            nil,
		"short":            {2, 0},
		"truncated entry":  ok[:len(ok)-1],
		"version 1":        acl(1, [3]uint32{tagUserObj, 6, 0}, [3]uint32{tagGroupObj, 4, 0}, [3]uint32{tagOther, 0, 0}),
		"unknown tag":      acl(2, [3]uint32{tagUserObj, 6, 0}, [3]uint32{tagGroupObj, 4, 0}, [3]uint32{tagOther, 0, 0}, [3]uint32{0x40, 0, 0}),
		"permission bits":  acl(2, [3]uint32{tagUserObj, 8, 0}, [3]uint32{tagGroupObj, 4, 0}, [3]uint32{tagOther, 0, 0}),
		"missing user_obj": acl(2, [3]uint32{tagGroupObj, 4, 0}, [3]uint32{tagOther, 0, 0}),
		"two group_obj":    acl(2, [3]uint32{tagUserObj, 6, 0}, [3]uint32{tagGroupObj, 4, 0}, [3]uint32{tagGroupObj, 4, 0}, [3]uint32{tagOther, 0, 0}),
		"two masks":        acl(2, [3]uint32{tagUserObj, 6, 0}, [3]uint32{tagGroupObj, 4, 0}, [3]uint32{tagOther, 0, 0}, [3]uint32{tagMask, 4, 0}, [3]uint32{tagMask, 4, 0}),
		"named, no mask":   acl(2, [3]uint32{tagUserObj, 6, 0}, [3]uint32{tagUser, 4, 5}, [3]uint32{tagGroupObj, 4, 0}, [3]uint32{tagOther, 0, 0}),
	}
	for name, b := range cases {
		if _, err := parsePOSIXACL(b); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}
