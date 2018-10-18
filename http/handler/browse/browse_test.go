package browse

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"io"
	"log"
	"mime/multipart"
	"net/http/httptest"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/portainer/agent"
	"github.com/portainer/agent/http/proxy"
)

const (
	volumeID   = "test"
	volumePath = "/var/lib/docker/volumes/" + volumeID + "/_data"
)

func TestVolumePutSuccess(t *testing.T) {
	handler := setup(false)
	filepath := "/testing"
	file := "put_test.txt"

	t.Run("BrowsePutInsideVolume", func(t *testing.T) {
		values := map[string]io.Reader{
			"file": mustOpen(file),
			"Path": strings.NewReader(filepath),
		}

		var b bytes.Buffer
		w := multipart.NewWriter(&b)
		formWriter(w, values)

		request := httptest.NewRequest("POST", "/browse/put?volumeID=test", &b)
		request.Header.Set("Content-Type", w.FormDataContentType())
		writer := httptest.NewRecorder()
		handler.ServeHTTP(writer, request)
		if writer.Result().StatusCode != 204 {
			t.Error("Failed to upload file.", writer.Result().Status)
		}
	})

	t.Run("ValidateChecksums", func(t *testing.T) {
		uploadedPath := path.Join(path.Join(volumePath, filepath), file)
		file1 := mustOpen(file)
		file2 := mustOpen(uploadedPath)
		if !validateChecksum(file1, file2) {
			t.Error("Checksums of initial file and uploaded file don't match")
		}
	})

	t.Run("BrowseDeleteInsideVolume", func(t *testing.T) {
		deletePath := path.Join(filepath, file)
		request := httptest.NewRequest("DELETE", "/browse/delete?volumeID=test&path="+deletePath, nil)
		writer := httptest.NewRecorder()
		handler.ServeHTTP(writer, request)
		if writer.Result().StatusCode != 204 {
			t.Error("Failed to delete file.", writer.Result().Status)
		}
	})
}
func TestPutSuccess(t *testing.T) {
	handler := setup(true)
	filepath := "./testing"
	file := "put_test.txt"

	t.Run("BrowsePut", func(t *testing.T) {
		values := map[string]io.Reader{
			"file": mustOpen(file),
			"Path": strings.NewReader(filepath),
		}
		var b bytes.Buffer
		w := multipart.NewWriter(&b)
		formWriter(w, values)

		request := httptest.NewRequest("POST", "/browse/put", &b)
		request.Header.Set("Content-Type", w.FormDataContentType())
		writer := httptest.NewRecorder()
		handler.ServeHTTP(writer, request)
		if writer.Result().StatusCode != 204 {
			t.Error("Failed to upload file.", writer.Result().Status)
		}
	})

	t.Run("ValidateChecksums", func(t *testing.T) {
		uploadedPath := path.Join(filepath, file)
		file1 := mustOpen(file)
		file2 := mustOpen(uploadedPath)
		if !validateChecksum(file1, file2) {
			t.Error("Checksums of initial file and uploaded file don't match")
		}
	})

	t.Run("BrowseDelete", func(t *testing.T) {
		deletePath := path.Join(filepath, file)
		request := httptest.NewRequest("DELETE", "/browse/delete?path="+deletePath, nil)
		writer := httptest.NewRecorder()
		handler.ServeHTTP(writer, request)
		if writer.Result().StatusCode != 204 {
			t.Error("Failed to delete file.", writer.Result().Status)
		}
	})
}

func TestPutMgmtDisabled(t *testing.T) {
	handler := setup(false)
	filepath := "./testing"
	file := "put_test.txt"

	t.Run("BrowsePut", func(t *testing.T) {
		values := map[string]io.Reader{
			"file": mustOpen(file),
			"Path": strings.NewReader(filepath),
		}
		var b bytes.Buffer
		w := multipart.NewWriter(&b)
		formWriter(w, values)

		request := httptest.NewRequest("POST", "/browse/put", &b)
		request.Header.Set("Content-Type", w.FormDataContentType())
		writer := httptest.NewRecorder()
		handler.ServeHTTP(writer, request)
		if writer.Result().StatusCode != 503 {
			t.Error("Upload should fail when Host Management capabilities are disabled", writer.Result().Status)
		}
	})
}

func TestVolumePutBinaryFile(t *testing.T) {
	handler := setup(false)
	file := "binary_test.jpg"
	filepath := "/binarytest"

	t.Run("BrowsePutInsideVolume", func(t *testing.T) {
		values := map[string]io.Reader{
			"file": mustOpen(file),
			"Path": strings.NewReader(filepath),
		}

		var b bytes.Buffer
		w := multipart.NewWriter(&b)
		formWriter(w, values)

		request := httptest.NewRequest("POST", "/browse/put?volumeID=test", &b)
		request.Header.Set("Content-Type", w.FormDataContentType())
		writer := httptest.NewRecorder()
		handler.ServeHTTP(writer, request)
		if writer.Result().StatusCode != 204 {
			t.Error("Failed to upload file.", writer.Result().Status)
		}
	})

	t.Run("ValidateChecksums", func(t *testing.T) {
		uploadedPath := path.Join(path.Join(volumePath, filepath), file)
		file1 := mustOpen(file)
		file2 := mustOpen(uploadedPath)
		if !validateChecksum(file1, file2) {
			t.Error("Checksums of initial file and uploaded file don't match")
		}
	})

	t.Run("BrowseDeleteFromVolume", func(t *testing.T) {
		deletePath := path.Join(filepath, file)
		request := httptest.NewRequest("DELETE", "/browse/delete?volumeID=test&path="+deletePath, nil)
		writer := httptest.NewRecorder()
		handler.ServeHTTP(writer, request)
		if writer.Result().StatusCode != 204 {
			t.Error("Failed to delete file.", writer.Result().Status)
		}
	})
}

func TestBrowseFail(t *testing.T) {
	handler := setup(false)
	file := "put_test.txt"

	t.Run("BrowsePutMissingPath", func(t *testing.T) {
		values := map[string]io.Reader{
			"file": mustOpen(file),
		}

		var b bytes.Buffer
		w := multipart.NewWriter(&b)
		formWriter(w, values)

		request := httptest.NewRequest("POST", "/browse/put?volumeID=test", &b)
		request.Header.Set("Content-Type", w.FormDataContentType())
		writer := httptest.NewRecorder()
		handler.ServeHTTP(writer, request)
		if writer.Result().StatusCode != 400 {
			t.Error("Failed to handle missing path", writer.Result().Status)
		}
	})

	t.Run("BrowsePutMissingFile", func(t *testing.T) {
		filepath := "/testing"
		values := map[string]io.Reader{
			"Path": strings.NewReader(filepath),
		}
		var b bytes.Buffer
		w := multipart.NewWriter(&b)
		formWriter(w, values)

		request := httptest.NewRequest("POST", "/browse/put?volumeID=test", &b)
		request.Header.Set("Content-Type", w.FormDataContentType())
		writer := httptest.NewRecorder()
		handler.ServeHTTP(writer, request)
		if writer.Result().StatusCode != 400 {
			t.Error("Failed to handle missing file", writer.Result().Status)
		}
	})

	t.Run("BrowsePutUnableToStoreFile", func(t *testing.T) {
		filepath := "/testing"
		values := map[string]io.Reader{
			"file": mustOpen(file),
			"Path": strings.NewReader(filepath),
		}

		var b bytes.Buffer
		w := multipart.NewWriter(&b)
		formWriter(w, values)

		request := httptest.NewRequest("POST", "/browse/put", &b)
		request.Header.Set("Content-Type", w.FormDataContentType())
		writer := httptest.NewRecorder()
		handler.ServeHTTP(writer, request)
		if writer.Result().StatusCode != 503 {
			t.Error("Failed", writer.Result().Status)
		}
	})

	t.Run("BrowseDeleteMissingPath", func(t *testing.T) {
		request := httptest.NewRequest("DELETE", "/browse/delete?volumeID=test", nil)
		writer := httptest.NewRecorder()
		handler.ServeHTTP(writer, request)
		if writer.Result().StatusCode != 400 {
			t.Error("Didn't return an error for missing path", writer.Result().Status)
		}
	})
}

func mustOpen(f string) *os.File {
	r, err := os.Open(f)
	if err != nil {
		panic(err)
	}
	return r
}

func formWriter(w *multipart.Writer, values map[string]io.Reader) {

	for key, r := range values {
		var fw io.Writer
		var err error
		if x, ok := r.(io.Closer); ok {
			defer x.Close()
		}
		if x, ok := r.(*os.File); ok {
			if fw, err = w.CreateFormFile(key, x.Name()); err != nil {
				return
			}
		} else {
			if fw, err = w.CreateFormField(key); err != nil {
				return
			}
		}
		if _, err = io.Copy(fw, r); err != nil {
			return
		}

	}
	w.Close()
}

func setup(hostManagementEnabled bool) *Handler {
	var agentTags map[string]string
	var cs agent.ClusterService
	agentProxy := proxy.NewAgentProxy(cs, agentTags)

	return NewHandler(agentProxy)
}

func validateChecksum(file1 *os.File, file2 *os.File) bool {
	sum1 := md5.New()
	if _, err := io.Copy(sum1, file1); err != nil {
		log.Fatal(err)
	}

	sum2 := md5.New()
	if _, err := io.Copy(sum2, file2); err != nil {
		log.Fatal(err)
	}

	return hex.EncodeToString(sum1.Sum(nil)) == hex.EncodeToString(sum2.Sum(nil))
}
