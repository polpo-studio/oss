package aliyun

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"hash"
	"io"
	"io/ioutil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	aliyun "github.com/aliyun/aliyun-oss-go-sdk/oss"
	"github.com/polpo-studio/oss"
)

// Client Aliyun storage
type Client struct {
	*aliyun.Bucket
	Config *Config
}

// Config Aliyun client config
type Config struct {
	AccessID      string
	AccessKey     string
	Region        string
	Bucket        string
	Endpoint      string
	ACL           aliyun.ACLType
	ClientOptions []aliyun.ClientOption
	UseCname      bool
}

// New initialize Aliyun storage
func New(config *Config) *Client {
	var (
		err    error
		client = &Client{Config: config}
	)

	if config.Endpoint == "" {
		config.Endpoint = "oss-cn-hangzhou.aliyuncs.com"
	}

	if config.ACL == "" {
		config.ACL = aliyun.ACLPublicRead
	}

	if config.UseCname {
		config.ClientOptions = append(config.ClientOptions, aliyun.UseCname(config.UseCname))
	}

	Aliyun, err := aliyun.New(config.Endpoint, config.AccessID, config.AccessKey, config.ClientOptions...)

	if err == nil {
		client.Bucket, err = Aliyun.Bucket(config.Bucket)
	}

	if err != nil {
		panic(err)
	}

	return client
}

// Get receive file with given path
func (client Client) Get(path string) (file *os.File, err error) {
	readCloser, err := client.GetStream(path)

	if err == nil {
		if file, err = ioutil.TempFile("/tmp", "ali"); err == nil {
			defer readCloser.Close()
			_, err = io.Copy(file, readCloser)
			file.Seek(0, 0)
		}
	}

	return file, err
}

// GetStream get file as stream
func (client Client) GetStream(path string) (io.ReadCloser, error) {
	return client.Bucket.GetObject(client.ToRelativePath(path))
}

// Put store a reader into given path
func (client Client) Put(urlPath string, reader io.Reader) (*oss.Object, error) {
	if seeker, ok := reader.(io.ReadSeeker); ok {
		seeker.Seek(0, 0)
	}

	err := client.Bucket.PutObject(client.ToRelativePath(urlPath), reader, aliyun.ACL(client.Config.ACL))
	now := time.Now()

	return &oss.Object{
		Path:             urlPath,
		Name:             filepath.Base(urlPath),
		LastModified:     &now,
		StorageInterface: client,
	}, err
}

// Delete delete file
func (client Client) Delete(path string) error {
	return client.Bucket.DeleteObject(client.ToRelativePath(path))
}

// List list all objects under current path
func (client Client) List(path string) ([]*oss.Object, error) {
	var objects []*oss.Object

	results, err := client.Bucket.ListObjects(aliyun.Prefix(path))

	if err == nil {
		for _, obj := range results.Objects {
			objects = append(objects, &oss.Object{
				Path:             "/" + client.ToRelativePath(obj.Key),
				Name:             filepath.Base(obj.Key),
				LastModified:     &obj.LastModified,
				StorageInterface: client,
			})
		}
	}

	return objects, err
}

// GetEndpoint get endpoint, FileSystem's endpoint is /
func (client Client) GetEndpoint() string {
	if client.Config.Endpoint != "" {
		if strings.HasSuffix(client.Config.Endpoint, "aliyuncs.com") {
			return client.Config.Bucket + "." + client.Config.Endpoint
		}
		return client.Config.Endpoint
	}

	endpoint := client.Bucket.Client.Config.Endpoint
	for _, prefix := range []string{"https://", "http://"} {
		endpoint = strings.TrimPrefix(endpoint, prefix)
	}

	return client.Config.Bucket + "." + endpoint
}

var urlRegexp = regexp.MustCompile(`(https?:)?//((\w+).)+(\w+)/`)

// ToRelativePath process path to relative path
func (client Client) ToRelativePath(urlPath string) string {
	if urlRegexp.MatchString(urlPath) {
		if u, err := url.Parse(urlPath); err == nil {
			return strings.TrimPrefix(u.Path, "/")
		}
	}

	return strings.TrimPrefix(urlPath, "/")
}

// GetURL get public accessible URL
func (client Client) GetURL(path string) (url string, err error) {
	if client.Config.ACL == aliyun.ACLPrivate {
		return client.Bucket.SignURL(client.ToRelativePath(path), aliyun.HTTPGet, 60*60) // 1 hour
	}
	return path, nil
}

func (client Client) GetUploadPolicy(prefix string, maxSize int32, expireInSeconds int32) (policy *oss.UploadPolicy, err error) {
	now := time.Now().Unix()
	expireEnd := now + int64(expireInSeconds)

	var tokenExpire = time.Unix(expireEnd, 0).UTC().Format("2006-01-02T15:04:05Z")

	//create post policy json
	var cond oss.CondConfig
	cond.Expiration = tokenExpire

	var startWithCondition []interface{}
	startWithCondition = append(startWithCondition, "starts-with")
	startWithCondition = append(startWithCondition, "$key")
	startWithCondition = append(startWithCondition, prefix)

	cond.Conditions = append(cond.Conditions, startWithCondition)

	var sizeCondition []interface{}
	sizeCondition = append(sizeCondition, "content-length-range")
	sizeCondition = append(sizeCondition, 0)
	sizeCondition = append(sizeCondition, maxSize)

	cond.Conditions = append(cond.Conditions, sizeCondition)

	//calculate signature
	result, _ := json.Marshal(cond)
	policyStr := base64.StdEncoding.EncodeToString(result)

	h := hmac.New(func() hash.Hash { return sha1.New() }, []byte(client.Config.AccessKey))

	_, err = io.WriteString(h, policyStr)

	if err != nil {
		return nil, err
	}

	signedStr := base64.StdEncoding.EncodeToString(h.Sum(nil))

	return &oss.UploadPolicy{
		AccessKeyId: client.Config.AccessID,
		Host:        client.Config.Endpoint,
		Expire:      expireEnd,
		Signature:   signedStr,
		Directory:   prefix,
		Policy:      policyStr,
	}, nil
}
