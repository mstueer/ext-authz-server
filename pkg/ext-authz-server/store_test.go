// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package extauthzserver

import (
	"crypto/sha1" // #nosec G505 -- test only
	"encoding/base64"
	"fmt"
	"testing/fstest"

	"github.com/gardener/gardener/pkg/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/tredoe/osutil/user/crypt/sha512_crypt"
	"golang.org/x/crypto/bcrypt"
)

var _ = Describe("Store", func() {
	Describe("#readSecrets", func() {
		It("should parse bcrypt credentials correctly", func() {
			testFs := fstest.MapFS{
				"app": &fstest.MapFile{
					Data: testCredentials("foo", "bar"),
				},
			}
			secrets, err := readSecrets(testFs)
			Expect(err).NotTo(HaveOccurred())
			Expect(secrets).To(HaveKey("app"))
			a := secrets["app"]
			Expect(a.username).To(Equal("foo"))
			Expect(bcrypt.CompareHashAndPassword(a.hashedPassword, []byte("bar"))).NotTo(HaveOccurred())
		})

		It("should parse SHA1 credentials correctly", func() {
			testFs := fstest.MapFS{
				"app": &fstest.MapFile{
					Data: testSHA1Credentials("admin", "my-password"),
				},
			}
			secrets, err := readSecrets(testFs)
			Expect(err).NotTo(HaveOccurred())
			Expect(secrets).To(HaveKey("app"))
			a := secrets["app"]
			Expect(a.username).To(Equal("admin"))
		})

		It("should parse SHA512-crypt credentials correctly", func() {
			testFs := fstest.MapFS{
				"app": &fstest.MapFile{
					Data: testSHA512CryptCredentials("ondemand-20261013", "my-password"),
				},
			}
			secrets, err := readSecrets(testFs)
			Expect(err).NotTo(HaveOccurred())
			Expect(secrets).To(HaveKey("app"))
			a := secrets["app"]
			Expect(a.username).To(Equal("ondemand-20261013"))
		})

		It("should return error if file does not contain htpasswd format", func() {
			testFs := fstest.MapFS{
				"app": &fstest.MapFile{
					Data: []byte("blablablub"),
				},
			}
			_, err := readSecrets(testFs)
			Expect(err).To(MatchError(ContainSubstring("does not contain valid basic auth")))
		})
	})

	Describe("#comparePassword", func() {
		It("should verify bcrypt password correctly", func() {
			hashed, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.DefaultCost)
			Expect(err).NotTo(HaveOccurred())
			Expect(comparePassword(hashed, []byte("secret"))).To(Succeed())
			Expect(comparePassword(hashed, []byte("wrong"))).NotTo(Succeed())
		})

		It("should verify SHA1 password correctly", func() {
			hash := sha1.Sum([]byte("my-password")) // #nosec G401
			storedHash := []byte("{SHA}" + base64.StdEncoding.EncodeToString(hash[:]))
			Expect(comparePassword(storedHash, []byte("my-password"))).To(Succeed())
			Expect(comparePassword(storedHash, []byte("wrong-password"))).NotTo(Succeed())
		})

		It("should reject invalid base64 in SHA1 hash", func() {
			storedHash := []byte("{SHA}not-valid-base64!!!")
			Expect(comparePassword(storedHash, []byte("anything"))).NotTo(Succeed())
		})

		It("should verify SHA512-crypt password correctly with custom rounds", func() {
			storedHash := sha512CryptHash("my-password", "$6$rounds=1000$saltsalt")
			Expect(comparePassword(storedHash, []byte("my-password"))).To(Succeed())
			Expect(comparePassword(storedHash, []byte("wrong-password"))).NotTo(Succeed())
		})

		It("should verify SHA512-crypt password correctly with default rounds", func() {
			storedHash := sha512CryptHash("my-password", "$6$saltsalt")
			Expect(comparePassword(storedHash, []byte("my-password"))).To(Succeed())
			Expect(comparePassword(storedHash, []byte("wrong-password"))).NotTo(Succeed())
		})

		It("should verify SHA512-crypt password with trailing newline", func() {
			storedHash := append(sha512CryptHash("my-password", "$6$rounds=1000$saltsalt"), '\n')
			Expect(comparePassword(storedHash, []byte("my-password"))).To(Succeed())
		})

		It("should reject invalid SHA512-crypt format", func() {
			storedHash := []byte("$6$invalid")
			Expect(comparePassword(storedHash, []byte("anything"))).NotTo(Succeed())
		})
	})

	Describe("#IsValid with SHA1 credentials", func() {
		It("should accept valid credentials with SHA1 hash", func() {
			s := &store{
				secrets: map[string]auth{
					"prometheus-aggregate": {
						username:       "admin",
						hashedPassword: sha1Hash("super-secret"),
					},
				},
			}
			header := basicAuthHeader("admin", "super-secret")
			Expect(s.IsValid("prometheus-aggregate", header)).To(Succeed())
		})

		It("should reject wrong password with SHA1 hash", func() {
			s := &store{
				secrets: map[string]auth{
					"prometheus-aggregate": {
						username:       "admin",
						hashedPassword: sha1Hash("correct-password"),
					},
				},
			}
			header := basicAuthHeader("admin", "wrong-password")
			Expect(s.IsValid("prometheus-aggregate", header)).NotTo(Succeed())
		})
	})

	Describe("#IsValid with SHA512-crypt credentials", func() {
		It("should accept valid credentials with SHA512-crypt hash", func() {
			s := &store{
				secrets: map[string]auth{
					"app": {
						username:       "ondemand-20261013",
						hashedPassword: sha512CryptHash("super-secret", "$6$rounds=1000$saltsalt"),
					},
				},
			}
			header := basicAuthHeader("ondemand-20261013", "super-secret")
			Expect(s.IsValid("app", header)).To(Succeed())
		})

		It("should reject wrong password with SHA512-crypt hash", func() {
			s := &store{
				secrets: map[string]auth{
					"app": {
						username:       "ondemand-20261013",
						hashedPassword: sha512CryptHash("correct-password", "$6$rounds=1000$saltsalt"),
					},
				},
			}
			header := basicAuthHeader("ondemand-20261013", "wrong-password")
			Expect(s.IsValid("app", header)).NotTo(Succeed())
		})
	})
})

func testCredentials(username, password string) []byte {
	GinkgoHelper()
	htpasswd, err := utils.CreateBcryptCredentials([]byte(username), []byte(password))
	Expect(err).NotTo(HaveOccurred())
	return htpasswd
}

func testSHA1Credentials(username, password string) []byte {
	hash := sha1.Sum([]byte(password)) // #nosec G401
	return fmt.Appendf(nil, "%s:{SHA}%s", username, base64.StdEncoding.EncodeToString(hash[:]))
}

func testSHA512CryptCredentials(username, password string) []byte {
	GinkgoHelper()
	return fmt.Appendf(nil, "%s:%s", username, sha512CryptHash(password, "$6$rounds=1000$saltsalt"))
}

func sha512CryptHash(password, salt string) []byte {
	GinkgoHelper()
	c := sha512_crypt.New()
	hash, err := c.Generate([]byte(password), []byte(salt))
	Expect(err).NotTo(HaveOccurred())
	return []byte(hash)
}

func sha1Hash(password string) []byte {
	hash := sha1.Sum([]byte(password)) // #nosec G401
	return fmt.Appendf(nil, "{SHA}%s", base64.StdEncoding.EncodeToString(hash[:]))
}

func basicAuthHeader(username, password string) string {
	return fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString(fmt.Appendf(nil, "%s:%s", username, password)))
}
