package pdfsigner

import (
	"errors"
	"fmt"

	"github.com/mailvibi/pdfsigner/internal/pdf"
)

// Errors returned by the signer. Use errors.Is to test for them.
var (
	ErrNoSigner               = errors.New("pdfsigner: no signer key")
	ErrNoCertificate          = errors.New("pdfsigner: no signing certificate")
	ErrKeyMismatch            = errors.New("pdfsigner: private key does not match signing certificate")
	ErrCertExpired            = errors.New("pdfsigner: signing certificate is not valid at signing time")
	ErrCertKeyUsage           = errors.New("pdfsigner: signing certificate key usage does not permit signing")
	ErrUnsupportedKey         = errors.New("pdfsigner: unsupported key type")
	ErrUnsupportedDigest      = errors.New("pdfsigner: unsupported digest algorithm")
	ErrEncryptedNeedsPassword = pdf.ErrNeedPassword
	ErrUnsupportedEncryption  = pdf.ErrUnsupportedEncryption
	ErrBrokenXref             = pdf.ErrBrokenXref
	ErrHeaderOffset           = pdf.ErrHeaderOffset
	ErrPermission             = errors.New("pdfsigner: document permissions do not allow signing")
	ErrCannotCertifySigned    = errors.New("pdfsigner: cannot certify a document that is already signed")
	ErrDocMDPForbids          = errors.New("pdfsigner: document certification (DocMDP P=1) forbids further signatures")
	ErrFieldLocked            = errors.New("pdfsigner: field lock (FieldMDP) forbids this signature")
	ErrFieldSigned            = errors.New("pdfsigner: signature field is already signed")
	ErrFieldNotSignature      = errors.New("pdfsigner: field exists and is not a signature field")
	ErrBadFieldName           = errors.New("pdfsigner: field name must not be empty or contain '.'")
	ErrXFAUnsupported         = errors.New("pdfsigner: dynamic XFA forms cannot be signed")
	ErrBadPage                = errors.New("pdfsigner: page number out of range")
	ErrSignatureMismatch      = errors.New("pdfsigner: signature does not verify against the signing certificate")
	ErrPreparedModified       = errors.New("pdfsigner: prepared document does not match prepared state")
	ErrNoTimestamper          = errors.New("pdfsigner: signature level requires a timestamp authority")
	ErrTimestamp              = errors.New("pdfsigner: timestamp failed")
	ErrRevoked                = errors.New("pdfsigner: certificate is revoked")
	ErrNoRevocationInfo       = errors.New("pdfsigner: no revocation information available")
	ErrGlyphUnsupported       = errors.New("pdfsigner: text contains characters not supported by the standard font; supply Appearance.Font")
	ErrBadImage               = errors.New("pdfsigner: unsupported or corrupt image")
	ErrNotSigned              = errors.New("pdfsigner: document contains no signatures")
)

// ContentsTooSmallError reports that the reserved /Contents space is too
// small for the final signature.
type ContentsTooSmallError struct {
	Have, Need int
}

func (e *ContentsTooSmallError) Error() string {
	return fmt.Sprintf("pdfsigner: signature needs %d bytes but only %d were reserved", e.Need, e.Have)
}
