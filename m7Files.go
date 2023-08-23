package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"github.com/gofrs/uuid"
	"github.com/shopspring/decimal"
	"golang.org/x/image/draw"
	"image"
	"image/jpeg"
	"image/png"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	_ = 1 << (10 * iota)
	KiB
	MiB
	GiB
	TiB
)

type FileSubmission struct {
	DataBase64    string `json:"base64"`
	Filename      string `json:"name"`
	ChatGroupUUID string `json:"chatId"`
	IsPrivate     bool   `json:"isPrivate"`
}

type FileMeta struct {
	Filename      string  `json:"t"`
	Path          string  `json:"pth"`
	SizeMB        float64 `json:"mb"`
	MimeType      string  `json:"mime"`
	Username      string  `json:"usr"`
	TimeCreated   string  `json:"ts"`
	ChatGroupUUID string  `json:"pid"`
	IsPrivate     bool    `json:"priv"`
}

func (db *GoDB) PublicFileEndpoints(r chi.Router, tokenAuth *jwtauth.JWTAuth) {
	r.Route("/files/public", func(r chi.Router) {
		r.Get("/get/{fileID}", db.handleFileGet())
	})
}

func (db *GoDB) ProtectedFileEndpoints(
	r chi.Router, tokenAuth *jwtauth.JWTAuth, userDB, chatGroupDB, chatMemberDB *GoDB,
) {
	r.Route("/files/private", func(r chi.Router) {
		r.Post("/create", db.handleFileCreate(userDB, chatGroupDB, chatMemberDB))
		r.Get("/meta/{fileID}", db.handleFileMetaGet(chatGroupDB, chatMemberDB))
	},
	)
}

func OpenFilesDatabase() *GoDB {
	db := OpenDB(
		"files", []string{},
	)
	return db
}

func GetBase64BinaryLength(b64 string) int {
	l := len(b64)
	eq := 0
	if l >= 2 {
		if b64[l-1] == '=' {
			eq++
		}
		if b64[l-2] == '=' {
			eq++
		}
		l -= eq
	}
	return (l*3 - eq) / 4
}

func GetBase64FileInformation(b64 string) (data, fileExt, fileType, mimeType string) {
	ix := strings.Index(b64, ";base64,")
	// Retrieve MIME type e.g. "image/gif" from "data:image/gif"
	mimeType = b64[5:ix]
	// Retrieve data which sits behind the prefix "dataBase64,"
	data = b64[ix+8:]
	// Retrieve file type e.g. "image" and file ending e.g. ".gif" from "image/gif"
	fileExt, fileType = GetBase64FileType(mimeType)
	return data, fileExt, fileType, mimeType
}

func GetBase64FileType(mimeType string) (fileExt, fileType string) {
	mimeSplit := strings.Split(mimeType, "/")
	fileType = mimeSplit[0]
	fileExtTmp := fmt.Sprintf("%s", mimeSplit[1])
	fileExt = ""
	switch fileType {
	case "text":
		switch fileExtTmp {
		case "plain":
			fileExt = ".txt"
			break
		case "css":
			fileExt = ".css"
			break
		case "html":
			fileExt = ".html"
			break
		case "xml":
			fileExt = ".xml"
			break
		case "csv":
			fileExt = ".csv"
			break
		}
		break
	case "image":
		switch fileExtTmp {
		case "gif":
			fileExt = ".gif"
			break
		case "jpeg":
			fileExt = ".jpg"
			break
		case "png":
			fileExt = ".png"
			break
		}
		break
	case "audio":
		switch fileExtTmp {
		case "mpeg":
			fileExt = ".mp3"
			break
		}
		break
	case "application":
		switch fileExtTmp {
		case "xml":
			fileExt = ".xml"
			break
		case "zip":
			fileExt = ".zip"
			break
		case "x-7z-compressed":
			fileExt = ".7z"
			break
		case "msword":
			fileExt = ".doc"
			break
		case "vnd.openxmlformats-officedocument.wordprocessingml.document":
			fileExt = ".docx"
			break
		case "gzip":
			fileExt = ".gz"
			break
		case "pdf":
			fileExt = ".pdf"
			break
		case "vnd.ms-powerpoint":
			fileExt = ".ppt"
			break
		case "vnd.openxmlformats-officedocument.presentationml.presentation":
			fileExt = ".pptx"
			break
		case "vnd.ms-excel":
			fileExt = ".xls"
			break
		case "vnd.openxmlformats-officedocument.spreadsheetml.sheet":
			fileExt = ".xlsx"
			break
		}
		break
	}
	return fileExt, fileType
}

func ExtractFilename(filename string) string {
	cleanFilename := ""
	// Remove file extension...
	extIx := strings.LastIndex(filename, ".")
	if extIx != -1 {
		// Exclude anything after the "."
		cleanFilename = filename[0:extIx]
	} else {
		cleanFilename = filename
	}
	// ...and illegal characters
	// Unix
	cleanFilename = strings.ReplaceAll(cleanFilename, "/", "-")
	// Windows
	re := regexp.MustCompile(`[><:"/\\|?*._]`)
	cleanFilename = re.ReplaceAllString(cleanFilename, "-")
	// Return without leading/trailing spaces
	return strings.TrimSpace(cleanFilename)
}

func getUserDir(user *User, workDir string) (string, error) {
	usernameClean := ExtractFilename(user.Username)
	dir := filepath.Join(workDir, "archive", usernameClean)
	err := checkArchiveDir(dir)
	if err != nil {
		return "", err
	}
	return dir, nil
}

func checkArchiveDir(userDir string) error {
	workDir, _ := os.Getwd()
	err := os.Mkdir(filepath.Join(workDir, "archive"), 0755)
	if err != nil && !os.IsExist(err) {
		return err
	}
	err = os.Mkdir(userDir, 0755)
	if err != nil && !os.IsExist(err) {
		return err
	}
	return nil
}

func (db *GoDB) SaveBase64AsFile(user *User, request *FileSubmission, fileSizeMB float64) (string, error) {
	data, fileExt, fileType, mimeType := GetBase64FileInformation(request.DataBase64)
	dec, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	// If an image is being submitted, we need to resize it to avoid having huge files on the server
	if fileType == "image" {
		r := bytes.NewReader(dec)
		var img image.Image
		if fileExt == ".png" {
			img, err = png.Decode(r)
		} else if fileExt == ".jpg" {
			img, err = jpeg.Decode(r)
		}
		if err != nil {
			return "", err
		}
		// We have the image now -> Check if resize is necessary
		bounds := img.Bounds()
		scaleX, scaleY, scaled := getScaledDimensions(bounds.Max.X, bounds.Max.Y, 1920, 1080)
		if scaled {
			// Scaled -> Resize necessary
			dst := image.NewRGBA(image.Rect(0, 0, scaleX, scaleY))
			draw.NearestNeighbor.Scale(dst, dst.Rect, img, img.Bounds(), draw.Over, nil)
			// Return resized bytes
			var b bytes.Buffer
			resizedBytes := bufio.NewWriter(&b)
			if fileExt == ".png" {
				err = png.Encode(resizedBytes, dst)
			} else if fileExt == ".jpg" {
				err = jpeg.Encode(resizedBytes, dst, nil)
			}
			if err != nil {
				return "", err
			}
			dec = b.Bytes()
		}
	}
	// Sanitize the filename and build full path
	filename := ExtractFilename(request.Filename)
	workDir, _ := os.Getwd()
	userDir, err := getUserDir(user, workDir)
	if err != nil {
		return "", err
	}
	// We will use a UUID for the internal file name
	// to avoid having to search for duplicate names
	uUIDFile, err := uuid.NewV7()
	if err != nil {
		return "", err
	}
	filePath := filepath.Join(userDir, fmt.Sprintf("%s%s", uUIDFile, fileExt))
	// Create new file
	f, err := os.Create(filePath)
	if err != nil {
		return "", err
	}
	defer func(f *os.File) {
		err = f.Close()
		if err != nil {
			fmt.Println(err)
		}
	}(f)
	// Write bytes
	if _, err = f.Write(dec); err != nil {
		return "", err
	}
	// Commit
	if err = f.Sync(); err != nil {
		return "", err
	}
	sizeMb, _ := decimal.NewFromFloat(fileSizeMB).Round(3).Float64()
	// Add file meta data to database
	fileMeta := &FileMeta{
		Filename:      fmt.Sprintf("%s%s", filename, fileExt),
		Path:          filePath,
		SizeMB:        sizeMb,
		MimeType:      mimeType,
		Username:      user.Username,
		TimeCreated:   TimeNowIsoString(),
		ChatGroupUUID: request.ChatGroupUUID,
		IsPrivate:     request.IsPrivate,
	}
	jsonEntry, err := json.Marshal(fileMeta)
	if err != nil {
		return "", err
	}
	uUID, err := db.Insert(jsonEntry, map[string]string{})
	return uUID, nil
}

func getScaledDimensions(imgWidth int, imgHeight int, maxWidth int, maxHeight int) (scaleX, scaleY int, scaled bool) {
	// Check if we need to resize
	if imgWidth < maxWidth && imgHeight < maxHeight {
		scaleX = imgWidth
		scaleY = imgHeight
		return scaleX, scaleY, false
	}
	// Calculate the ratio e.g. 2520x1080 will become 0.4285...
	var ratio float64
	w := float64(imgWidth)
	h := float64(imgHeight)
	if imgHeight < imgWidth {
		ratio = h / w
		// Set scaled dimensions e.g. 2520x1080 will become 1920x822 (respecting the original aspect ratio)
		scaleX = maxWidth
		scaleYTmp := float64(scaleX) * ratio
		scaleY = int(scaleYTmp)
	} else {
		ratio = w / h
		// Set scaled dimensions
		scaleY = maxHeight
		scaleXTmp := float64(scaleY) * ratio
		scaleX = int(scaleXTmp)
	}
	fmt.Println(ratio)
	return scaleX, scaleY, true
}

func (a *FileSubmission) Bind(_ *http.Request) error {
	if a.DataBase64 == "" {
		return errors.New("missing base64")
	}
	return nil
}

func (db *GoDB) handleFileCreate(userDB, chatGroupDB, chatMemberDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		// Retrieve POST payload
		request := &FileSubmission{}
		if err := render.Bind(r, request); err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Is a chat group referenced?
		if request.ChatGroupUUID != "" {
			chatGroup, chatMember, _, err := GetChatGroupAndMember(
				chatGroupDB, chatMemberDB, request.ChatGroupUUID, user.Username, "")
			if err != nil {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			canWrite := CheckWriteRights(chatMember.ChatMember, chatGroup.ChatGroup)
			if !canWrite {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
		}
		// Check file size
		fileSize := GetBase64BinaryLength(request.DataBase64)
		if fileSize > 20*MiB {
			http.Error(w, http.StatusText(http.StatusInsufficientStorage), http.StatusInsufficientStorage)
			return
		}
		fileSizeMB := float64(fileSize) / float64(1*MiB)
		uUID, err := db.SaveBase64AsFile(user, request, fileSizeMB)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		_, _ = fmt.Fprintln(w, uUID)
	}
}

func (db *GoDB) handleFileGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fileID := chi.URLParam(r, "fileID")
		if fileID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		response, ok := db.Get(fileID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		fileMeta := &FileMeta{}
		err := json.Unmarshal(response.Data, fileMeta)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Disposition",
			fmt.Sprintf("attachment; filename=\"%s\"", fileMeta.Filename))
		w.WriteHeader(http.StatusOK)
		http.ServeFile(w, r, fileMeta.Path)
	}
}

func (db *GoDB) handleFileMetaGet(chatGroupDB, chatMemberDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		fileID := chi.URLParam(r, "fileID")
		if fileID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		response, ok := db.Get(fileID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		fileMeta := &FileMeta{}
		err := json.Unmarshal(response.Data, fileMeta)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Is the file protected?
		if fileMeta.IsPrivate && fileMeta.ChatGroupUUID != "" {
			chatGroup, chatMember, _, err := GetChatGroupAndMember(
				chatGroupDB, chatMemberDB, fileMeta.ChatGroupUUID, user.Username, "")
			if err != nil {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			canRead := CheckReadRights(chatMember.ChatMember, chatGroup.ChatGroup)
			if !canRead {
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
		}
		// Sanitize
		fileMeta.Path = fmt.Sprintf("files/public/get/%s", response.uUID)
		// Respond
		render.JSON(w, r, fileMeta)
	}
}
