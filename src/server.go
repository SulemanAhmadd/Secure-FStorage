package main

import (
	"os"
	"log"
	"fmt"
	"time"
	"path"

	"net/http"
	"database/sql"
	"crypto/rand"
	"html/template"
	"path/filepath"
	"crypto/sha256"

	_ "github.com/lib/pq"
	"github.com/gorilla/csrf"
	"golang.org/x/crypto/pbkdf2"
	"github.com/gorilla/mux"
	"github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
	"github.com/didip/tollbooth"
	"github.com/unrolled/secure" 
	"github.com/gomodule/redigo/redis"
)


/* * * * * * * * * * * INITIALIZE DB AND CACHE * * * * * * * * * * * * * * * */

// Setup POSTGRES database
var db *sql.DB;
func initDB(){

	var err error
	
	conn_str := "host=postgres-db dbname=file_storage user=testuser password=testpass sslmode=disable"
	db, err = sql.Open("postgres", conn_str)
	if err != nil {
		log.Println("Connection to the database failed")
		panic(err)
	}
	err = db.Ping()

	create_table_str := `create table users (
						username text primary key, 
						password text,
						key_salt text,
						filepaths varchar[]
					);`

	_, err = db.Query(create_table_str)
	if err != nil {
		log.Fatal("POSTGRES: ", err)
		return
	}
}


// Setup REDIS Cache
var cache redis.Conn
func initCache() {
	conn, err := redis.DialURL("redis://redis-db")
	if err != nil {
		log.Fatal("REDIS: ", err)
		return
	}

	cache = conn
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */



/* * * * * * * * * * * TEMPLATE RENDERING METHODS * * * * * * * * * * * * * * */

// Base render call for setting up an html file with given given context
func render(w http.ResponseWriter, filename string, context interface{}) {
	tmpl, err := template.ParseFiles(filename)
	if err != nil {
		log.Println(err)
		http.Error(w, "Sorry, something went wrong", http.StatusInternalServerError)
	}

	if err := tmpl.Execute(w, context); err != nil {
		log.Println(err)
		http.Error(w, "Sorry, something went wrong", http.StatusInternalServerError)
	}
}

// Renders Login page for any user
func render_login (w http.ResponseWriter, r *http.Request, error_msg string) {
	    context := struct {
        ErrorMsg string
        CSRFField template.HTML
    }{
        ErrorMsg: error_msg,
        CSRFField: csrf.TemplateField(r),
    }

	render(w, "templates/login.html", context)
}

// Renders Registration page for any user
func render_registration (w http.ResponseWriter, r *http.Request, error_msg string) {

    context := struct {
        ErrorMsg string
        CSRFField template.HTML
    }{
        ErrorMsg: error_msg,
        CSRFField: csrf.TemplateField(r),
    }

	render(w, "templates/register.html", context)
}

// Renders Home page for a specific user
func render_home(w http.ResponseWriter, r *http.Request, error_msg string) {

	// Determine which user is this. Validity already determined
	token, _ := r.Cookie("session_token")
	sessionToken := token.Value
	username, _ := redis.String(cache.Do("GET", sessionToken))

	// Get filenames of this user
	filenames, err := get_filenames(db, username)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Setup template values in html
	context := struct {
        UserName string
        ErrorMsg string
        Filenames []string
        CSRFField template.HTML
    }{
    	UserName: username,
        ErrorMsg: error_msg,
        Filenames: filenames,
        CSRFField: csrf.TemplateField(r),
    }

	render(w, "templates/index.html", context)
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */



/* * * * * * * * * * * LOGOUT HANDLING ROUTINE * * * * * * * * * * * * * * * */

/* Handles user log out event and deletes all session tokens */
func Logout(w http.ResponseWriter, r *http.Request) {

	// Confirm session validity. If session already expired, already logged out
	if !verify_session_token(w, r) {
		return
	}

	// Fetch user session details
	token, _ := r.Cookie("session_token")
	sessionToken := token.Value
	username, _ := redis.String(cache.Do("GET", sessionToken))

	// Delete sesstion token
	_, err := cache.Do("DEL", sessionToken)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Delete encryption key
	_, err = cache.Do("DEL", username)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	log.Printf("User %s logged out", username)
	http.Redirect(w, r, "/home", 302)
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */



/* * * * * * * * * * * FILE DOWNLOAD HANDLING ROUTINE * * * * * * * * * * * * * * * */

/* Handles and validates file RETRIEVE API call */
func Download(w http.ResponseWriter, r *http.Request) {

	// Confirm session validity
	if !verify_session_token(w, r) {
		return
	}

	// Determine which user is this
	token, _ := r.Cookie("session_token")
	sessionToken := token.Value
	username, _ := redis.String(cache.Do("GET", sessionToken))

	// Validate File Path
	urlpath := path.Clean(r.URL.Path)
	filename := path.Base(urlpath)
	if ok, err_msg := validate_filename(filename); !ok {
		render_home(w, r, err_msg)
		return
	}

	// Check if file exists on server for this user
	filenames, err := get_filenames(db, username)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if ok := stringInSlice(filename, filenames); !ok {
		log.Printf("User: %s attempted unauthorized file access", username)
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// Access file and decrypt
	filepath := filepath.Join(UPLOAD_PATH, username, filename)
	encryption_key, _ := redis.String(cache.Do("GET", username))
	userdata, err := decrypt_and_retrieve(filepath, encryption_key)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	log.Printf("User %s downloaded file %s", username, filename)

	// Send the file back to user
	w.Header().Add("Content-Disposition", "Attachment")
	http.ServeContent(w, r, filename, time.Now(), userdata)
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */



/* * * * * * * * * * * FILE UPLOAD HANDLING ROUTINE * * * * * * * * * * * * * * * */

/* Handles and validates file STORE API call */
func Upload(w http.ResponseWriter, r *http.Request) {

	// Confirm session validity. If not valid, then do not allow to upload
	if !verify_session_token(w, r) {
		return
	}

	// Validate file size
	r.Body = http.MaxBytesReader(w, r.Body, MAX_UPLOAD_SIZE)
	if err := r.ParseMultipartForm(MAX_UPLOAD_SIZE); err != nil {
		render_home(w, r, "Error: FILE TOO BIG TO UPLOAD!")
		return
	}

	// Parse and validate file and post parameters
	file, file_handler, err := r.FormFile("uploadFile")
	if err != nil {
		render_home(w, r, "Error: INVALID FILE UPLOAD!")
		return
	}
	defer file.Close()
	fileBytes, err := read_file_data(file)
	if err != nil {
		render_home(w, r, "Error: CAN NOT PARSE FILE!")
		return
	}

	// Validate File name
	filename := file_handler.Filename
	if ok, err_msg := validate_filename(filename); !ok {
		render_home(w, r, err_msg)
		return
	}
	filename = filepath.Base(filename)

	// Get Username and Key
	token, _ := r.Cookie("session_token")
	sessionToken := token.Value
	username, _ := redis.String(cache.Do("GET", sessionToken))
	encryption_key, _ := redis.String(cache.Do("GET", username))

	// Validate if file already exists
	filenames, err := get_filenames(db, username)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if ok := stringInSlice(filename, filenames); ok {
		render_home(w, r, "Error: A FILE WITH THIS NAME ALREADY EXISTS!")
		return
	}

	// Encrypt file data and write to filesystem
	new_path := filepath.Join(UPLOAD_PATH, username, filename)
	err = encrypt_and_store(new_path, fileBytes, encryption_key)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Enter filename metadata in database after file write successful
	err = append_filename_db(db, username, filename)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	log.Printf("User %s uploaded file %s", username, filename)
	http.Redirect(w, r, "/home", 302)
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */



/* * * * * * * * * * * HOME PAGE HANDLING ROUTINE * * * * * * * * * * * * * * * */

/* Handles and validates GET requests for home page */
func Home(w http.ResponseWriter, r *http.Request) {

	// Confirm session validity. If session expired sent to login page
	if !verify_session_token(w, r) {
		render_login(w, r, "You have been logged out!")
		return
	}

	// Else show home page
	render_home(w, r, "")
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */



/* * * * * * * * * * * SIGNIN HANDLING ROUTINES * * * * * * * * * * * * * * * */

/* Handles and validates GET requests for signin/login page */
func SignInPage(w http.ResponseWriter, r *http.Request) {

	// Check session token. If exists redirect to home page
	if check_session_token(r) == VALID_SESS {
		http.Redirect(w, r, "/home", 302)
		return
	}

	// Else prompt for login
	render_login(w, r, "")
}

/* Handles and validates POST requests for signin/login */
func SignIn(w http.ResponseWriter, r *http.Request) {

	// Check session token. If exists redirect to home page
	if check_session_token(r) == VALID_SESS {
		http.Redirect(w, r, "/home", 302)
		return
	}

	// Load submitted POST Form values
	r.ParseForm()

	// Parsing POST Data
	creds := &JSON_Auth{}
	creds.Username = r.FormValue("username")
	creds.Password = r.FormValue("password")

	// Input validation for Username
	if ok, _ := validate_username(creds.Username); !ok {
		render_login(w, r, "Error: Invalid Username Format!")
		return
	}

	// Input Validation for Password
	if ok, _ := validate_password(creds.Password); !ok {
		render_login(w, r, "Error: Invalid Password Format!")
		return
	}

	// Verify the username in db
	storedCreds := &DB_Auth{}
	err := db.QueryRow("select password from users where username=$1", creds.Username).Scan(&storedCreds.Password)
	if err != nil {
		// If an entry with the username does not exist
		if err == sql.ErrNoRows {
			render_login(w, r, "Error: No such User Exists!")
			return
		}

		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Verify the password
	if err = bcrypt.CompareHashAndPassword([]byte(storedCreds.Password), []byte(creds.Password)); err != nil {
		render_login(w, r, "Error: Incorrect Password!")
		return
	}

	// Fetch the Salt value for this user
	err = db.QueryRow("select key_salt from users where username=$1", creds.Username).Scan(&storedCreds.Keysalt)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Store PBKDF key in cache for encrypting files for this user, with a 5 minute expiry time
	user_encryption_key := pbkdf2.Key([]byte(creds.Password), []byte(storedCreds.Keysalt), 4096, sha256.Size, sha256.New)
	_, err = cache.Do("SETEX", creds.Username, "300", user_encryption_key)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Create a valid session token and set in cache
	u, _ := uuid.NewV4()
	sessionToken := u.String() 

	_, err = cache.Do("SETEX", sessionToken, "300", creds.Username)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Set Cookie Expiry to 5 minutes
	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   sessionToken,
		Expires: time.Now().Add(300 * time.Minute),
		HttpOnly: true,
	})

	log.Printf("User %s logged in", creds.Username)
	http.Redirect(w, r, "/home", 302)
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */



/* * * * * * * * * * * SIGNUP HANDLING ROUTINES * * * * * * * * * * * * * * * */

/* Handles and validates GET requests for registration page */
func SignUpPage(w http.ResponseWriter, r *http.Request) {

	// Check session token. If exists redirect to home page
	if check_session_token(r) == VALID_SESS {
		http.Redirect(w, r, "/home", 302)
		return
	}

	// Else prompt for registration
	render_registration(w, r, "")
}

/* Handles and validates POST requests for registration */
func SignUp(w http.ResponseWriter, r *http.Request) {

	// Check session token. If exists redirect to home page
	if check_session_token(r) == VALID_SESS {
		http.Redirect(w, r, "/home", 302)
		return
	}

	// Load submitted POST Form values
	r.ParseForm()

	// Parsing POST Data
	creds := &JSON_Auth{}
	creds.Username = r.FormValue("username")
	creds.Password = r.FormValue("password")
	creds.RepeatPW = r.FormValue("psw-repeat")

	// Confirm Password Equivalence
	if creds.Password != creds.RepeatPW {
		render_registration(w, r, "Error: Password Mismatch!")
		return
	}

	// Check Username Requirements
	if ok, err := validate_username(creds.Username); !ok {
		render_registration(w, r, err)
		return
	}

	// Check Password Requirements
	if ok, err := validate_password(creds.Password); !ok {
		render_registration(w, r, err)
		return
	}

	// Check if username already registered
	err := db.QueryRow("select 1 from users where username=$1", creds.Username).Scan()
	if err != sql.ErrNoRows {
		render_registration(w, r, "Error: Username Already Exists!")
		return
	}

	// Salt and Hash the password using the bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.MinCost)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Generate Salt for Pbkdf
	key_salt := make([]byte, 8)
	rand.Read(key_salt)
	key_salt_str := fmt.Sprintf("%x", key_salt)

	// Insert new user credentials into database
	if _, err = db.Query("insert into users values ($1, $2, $3, $4)", creds.Username, string(hashedPassword), key_salt_str, "{}"); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Store PBKDF key in cache for encrypting files for this user, with a 5 minute expiry time
	user_encryption_key := pbkdf2.Key([]byte(creds.Password), []byte(key_salt_str), 4096, sha256.Size, sha256.New)
	_, err = cache.Do("SETEX", creds.Username, "300", user_encryption_key)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Create a session token and set in memory
	u, _ := uuid.NewV4()
	sessionToken := u.String() 

	_, err = cache.Do("SETEX", sessionToken, "300", creds.Username)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Set Cookie Expiry to 5 minutes
	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   sessionToken,
		Expires: time.Now().Add(300 * time.Minute),
		HttpOnly: true,
	})

	// Create a folder on filesystem for storing this users files
	folderpath := filepath.Join(UPLOAD_PATH, creds.Username) 
	if _, err := os.Stat(folderpath); os.IsNotExist(err) {
   		os.Mkdir(folderpath, 0700)
	} else {
		os.RemoveAll(folderpath)
		os.Mkdir(folderpath, 0700) 
	}

	log.Printf("A new user registered: %s", creds.Username)
	http.Redirect(w, r, "/home", 302)
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */


func main() {

	// Make sure that docker services are up
	time.Sleep(5 * time.Second)

	// Secure Middleware configurations
	secureMiddleware := secure.New(secure.Options{
	    FrameDeny:             true,
	    ContentTypeNosniff:    true,
	    BrowserXssFilter:      true,
	    ContentSecurityPolicy: "default-src 'self'; style-src 'self' 'unsafe-inline';",
	    IsDevelopment: true,
    })

    // Create a new router instance
	router := mux.NewRouter()

	// Integrating secure middleware
	router.Use(secureMiddleware.Handler)

	// Only allow five requests per second to server
	limiter := tollbooth.NewLimiter(5, nil)

	// Initializing PostGres 
	log.Println("Starting Persistent Storage...")
	initDB()

	// Initializing Redis 
	log.Println("Starting Cache Storage...")
	initCache()

	// Root Route Handler call
	router.HandleFunc("/", SignUpPage).Methods("GET")

	// Registering a new user
	router.Handle("/signup", tollbooth.LimitFuncHandler(limiter, SignUp)).Methods("POST")
	router.HandleFunc("/signup", SignUpPage).Methods("GET")

	// Logging in User
	router.Handle("/signin", tollbooth.LimitFuncHandler(limiter, SignIn)).Methods("POST")
	router.HandleFunc("/signin", SignInPage).Methods("GET")

	// User Storage View
	router.HandleFunc("/home", Home).Methods("GET")

	// Upload a new file
	router.Handle("/upload", tollbooth.LimitFuncHandler(limiter, Upload)).Methods("POST")

	// Download a file
	router.HandleFunc(`/download/{name:[a-zA-Z0-9_\-.(),]+}`, Download).Methods("GET")

	// Logout User
	router.HandleFunc("/logout", Logout).Methods("POST")

	// Fetch Port Number
	port := os.Getenv("PORT")

	// Fetch CSRF_KEY
	csrfkey := os.Getenv("CSRF_KEY")

	// Server listening
	log.Println("** Web Server Started on Port " + port + " **")

	// Start server with CSRF protection
	err := http.ListenAndServe(":" + port, csrf.Protect([]byte(csrfkey), csrf.Secure(false))(router)); 

	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}

}