package hostfile

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	aclVersion = 2

	tagUserObj  = 0x01
	tagUser     = 0x02
	tagGroupObj = 0x04
	tagGroup    = 0x08
	tagMask     = 0x10
	tagOther    = 0x20

	permR = 0o4
	permW = 0o2
)

type aclEntry struct {
	id   uint32
	perm uint16
}

// posixACL holds the group class of a system.posix_acl_access value. Owner and other
// permissions come from Node.Mode, which the kernel keeps equal to USER_OBJ and OTHER.
type posixACL struct {
	groupObj uint16
	mask     uint16
	users    []aclEntry
	groups   []aclEntry
}

func (a *posixACL) effective(perm uint16) uint16 { return perm & a.mask }

// parsePOSIXACL parses the little-endian xattr value. Anything it cannot account for is an
// error, and an error refuses.
func parsePOSIXACL(b []byte) (posixACL, error) {
	var a posixACL
	if len(b) < 4 || (len(b)-4)%8 != 0 {
		return a, errors.New("bad length")
	}
	if v := binary.LittleEndian.Uint32(b); v != aclVersion {
		return a, fmt.Errorf("version %d", v)
	}
	var userObj, groupObj, other, mask int
	a.mask = 0o7
	for off := 4; off < len(b); off += 8 {
		tag := binary.LittleEndian.Uint16(b[off:])
		perm := binary.LittleEndian.Uint16(b[off+2:])
		id := binary.LittleEndian.Uint32(b[off+4:])
		if perm&^0o7 != 0 {
			return a, errors.New("bad permission bits")
		}
		switch tag {
		case tagUserObj:
			userObj++
		case tagGroupObj:
			groupObj++
			a.groupObj = perm
		case tagOther:
			other++
		case tagMask:
			mask++
			a.mask = perm
		case tagUser:
			a.users = append(a.users, aclEntry{id, perm})
		case tagGroup:
			a.groups = append(a.groups, aclEntry{id, perm})
		default:
			return a, fmt.Errorf("unknown tag %#x", tag)
		}
	}
	if userObj != 1 || groupObj != 1 || other != 1 || mask > 1 {
		return a, errors.New("entry counts")
	}
	if mask == 0 && (len(a.users) > 0 || len(a.groups) > 0) {
		return a, errors.New("named entries without a mask")
	}
	return a, nil
}
