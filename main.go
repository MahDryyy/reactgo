package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"database/sql"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/generative-ai-go/genai"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/api/option"
)

var DB *sql.DB

var jwtSecret = []byte("your_secret_key") // Ganti dengan secret key Anda

// Struct untuk makanan
type Food struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	ExpiryDate string `json:"expiry_date"`
}

// Request untuk menambah makanan
type AddFoodRequest struct {
	Name       string `json:"name"`
	ExpiryDate string `json:"expiry_date"`
}

// Request untuk resep
type RecipeRequest struct {
	FoodName string `json:"food_name"`
}

// Response untuk resep
type RecipeResponse struct {
	Recipe string `json:"recipe"`
}

// Claims untuk JWT (dengan role)
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// Fungsi untuk inisialisasi database
func InitDB() {
	var err error
	DB, err = sql.Open("mysql", "root:@tcp(127.0.0.1:3306)/savebite") // Sesuaikan username dan password dengan konfigurasi Anda
	if err != nil {
		log.Fatalf("Gagal terhubung ke database: %v", err)
	}

	err = DB.Ping()
	if err != nil {
		log.Fatalf("Tidak bisa terhubung ke database: %v", err)
	}

	fmt.Println("✅ Berhasil terhubung ke database")
}

// Fungsi untuk menambah makanan ke database
func AddFood(name, expiryDate string) error {
	_, err := DB.Exec("INSERT INTO foods (name, expiry_date) VALUES (?, ?)", name, expiryDate)
	return err
}

// Fungsi untuk mengambil semua makanan dari database
func GetFoods() ([]Food, error) {
	rows, err := DB.Query("SELECT id, name, expiry_date FROM foods")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var foods []Food
	for rows.Next() {
		var food Food
		if err := rows.Scan(&food.ID, &food.Name, &food.ExpiryDate); err != nil {
			return nil, err
		}
		foods = append(foods, food)
	}

	return foods, nil
}

// Fungsi untuk menghapus makanan berdasarkan ID
func DeleteFood(id string) error {
	// Log ID yang diterima untuk memastikan ID benar
	fmt.Println("Menghapus makanan dengan ID:", id)

	// Periksa apakah makanan dengan ID tersebut ada
	var exists bool
	err := DB.QueryRow("SELECT EXISTS(SELECT 1 FROM foods WHERE id = ?)", id).Scan(&exists)
	if err != nil {
		log.Printf("Error saat memeriksa eksiste nsi makanan: %v", err)
		return fmt.Errorf("gagal memeriksa eksistensi makanan: %v", err)
	}

	// Jika makanan tidak ditemukan
	if !exists {
		return fmt.Errorf("Makanan dengan ID %s tidak ditemukan", id)
	}

	// Hapus data makanan jika ditemukan
	_, err = DB.Exec("DELETE FROM foods WHERE id = ?", id)
	if err != nil {
		log.Printf("Error saat menghapus makanan: %v", err)
		return fmt.Errorf("gagal menghapus makanan: %v", err)
	}

	// Verifikasi bahwa data sudah dihapus
	var checkExists bool
	err = DB.QueryRow("SELECT EXISTS(SELECT 1 FROM foods WHERE id = ?)", id).Scan(&checkExists)
	if err != nil {
		log.Printf("Error saat memverifikasi penghapusan makanan: %v", err)
		return fmt.Errorf("gagal memverifikasi penghapusan makanan: %v", err)
	}

	// Jika makanan masih ada, berarti penghapusan gagal
	if checkExists {
		return fmt.Errorf("Gagal menghapus makanan dengan ID %s", id)
	}

	return nil
}

// Fungsi untuk menambah resep makanan ke database
func AddFoodRecipe(foodID int, recipe string) error {
	_, err := DB.Exec("INSERT INTO food_recipes (food_id, recipe) VALUES (?, ?)", foodID, recipe)
	return err
}

// Fungsi untuk menghasilkan JWT token
func GenerateJWT(username string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour) // Token berlaku selama 1 hari
	claims := &Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(), // Menggunakan Unix() untuk mendapatkan nilai int64
			Issuer:    "myapp",
		},
	}

	// Membuat token dengan algoritma HMAC dan signing key
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// Middleware untuk memverifikasi token JWT
func ValidateToken(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		c.JSON(401, gin.H{"error": "Token tidak ditemukan"})
		c.Abort()
		return
	}

	tokenString = tokenString[7:] // Menghapus prefix "Bearer "

	// Mem-parsing token dan memverifikasi kebenarannya
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Memastikan token menggunakan algoritma yang benar
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("metode signing tidak valid")
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		c.JSON(401, gin.H{"error": "Token tidak valid"})
		c.Abort()
		return
	}

	// Menyimpan informasi user ke context untuk akses di handler berikutnya
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		c.Set("username", claims.Username)
		c.Next()
	} else {
		c.JSON(401, gin.H{"error": "Token tidak valid"})
		c.Abort()
	}
}

// Fungsi login untuk menghasilkan token JWT
func loginHandler(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Cari pengguna berdasarkan username
	var storedPasswordHash string
	err := DB.QueryRow("SELECT password FROM users WHERE username = ?", req.Username).Scan(&storedPasswordHash)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Verifikasi password yang dimasukkan dengan hash yang ada di database
	err = bcrypt.CompareHashAndPassword([]byte(storedPasswordHash), []byte(req.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Menghasilkan JWT token jika login berhasil
	token, err := GenerateJWT(req.Username)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to generate token"})
		return
	}

	// Mengirimkan token JWT sebagai respons
	c.JSON(200, gin.H{"token": token})
}

// Fungsi untuk register pengguna baru (user)
func registerHandler(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"` // Role bisa ditentukan oleh admin
	}

	// Bind data JSON ke struct
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Admin hanya bisa menetapkan role `admin` atau `user`
	if req.Role != "user" && req.Role != "admin" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Role must be 'admin' or 'user'"})
		return
	}

	// Cek apakah username sudah ada
	var existingUsername string
	err := DB.QueryRow("SELECT username FROM users WHERE username = ?", req.Username).Scan(&existingUsername)
	if err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
		return
	}

	// Hash password
	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	// Simpan pengguna ke database
	_, err = DB.Exec("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", req.Username, hashedPassword, req.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User registered successfully"})
}

// Fungsi untuk hash password
func hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// Fungsi untuk memeriksa role pengguna
func CheckRole(role string) gin.HandlerFunc {
	return func(c *gin.Context) {
		username := c.MustGet("username").(string) // Mendapatkan username dari context

		// Cek role pengguna di database (misalnya dengan query)
		var userRole string
		err := DB.QueryRow("SELECT role FROM users WHERE username = ?", username).Scan(&userRole)
		if err != nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "Role tidak ditemukan"})
			c.Abort()
			return
		}

		// Pastikan role pengguna sesuai
		if userRole != role {
			c.JSON(http.StatusForbidden, gin.H{"error": "Akses ditolak, role tidak sesuai"})
			c.Abort()
			return
		}

		c.Next() // Lanjutkan ke handler berikutnya jika role cocok
	}
}

// Route untuk melihat semua user
func getAllUsersHandler(c *gin.Context) {
	// Hanya admin yang bisa mengakses endpoint ini
	username := c.MustGet("username").(string)
	var userRole string
	err := DB.QueryRow("SELECT role FROM users WHERE username = ?", username).Scan(&userRole)
	if err != nil || userRole != "admin" {
		c.JSON(http.StatusForbidden, gin.H{"error": "Only admin can view all users"})
		return
	}

	// Ambil semua user dari database
	rows, err := DB.Query("SELECT username, role FROM users")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch users"})
		return
	}
	defer rows.Close()

	var users []map[string]interface{}
	for rows.Next() {
		var username, role string
		err := rows.Scan(&username, &role)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read users"})
			return
		}
		users = append(users, map[string]interface{}{"username": username, "role": role})
	}

	c.JSON(http.StatusOK, gin.H{"users": users})
}

func main() {
	// Inisialisasi database
	InitDB()

	r := gin.Default()

	// Route untuk register pengguna baru
	r.POST("/register", registerHandler)

	// Route untuk register pengguna baru oleh Admin (Admin hanya yang bisa memberikan role 'admin')
	r.POST("/register/admin", ValidateToken, CheckRole("admin"), registerHandler)

	// Route untuk login pengguna
	r.POST("/login", loginHandler)

	// Route untuk melihat semua user (Hanya bisa diakses oleh admin)
	r.GET("/users", ValidateToken, getAllUsersHandler)

	// Admin/User: Bisa menambah makanan
	r.POST("/foods", ValidateToken, func(c *gin.Context) {
		var req AddFoodRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Format request salah"})
			return
		}
		err := AddFood(req.Name, req.ExpiryDate)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyimpan makanan"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Makanan berhasil disimpan"})
	})

	// Admin/User: Bisa menghapus makanan
	r.DELETE("/foods/:id", ValidateToken, func(c *gin.Context) {
		id := c.Param("id")
		err := DeleteFood(id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Makanan berhasil dihapus"})
	})

	// User: Bisa melihat makanan
	r.GET("/foods", ValidateToken, func(c *gin.Context) {
		foods, err := GetFoods()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil data"})
			return
		}
		c.JSON(http.StatusOK, foods)
	})

	// User: Bisa meminta resep
	r.POST("/recipe", ValidateToken, func(c *gin.Context) {
		var req RecipeRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Format request salah"})
			return
		}
		apiKey := os.Getenv("API_KEY")
		if apiKey == "" {
			log.Fatal("API key tidak ditemukan! Pastikan sudah diset di environment variable.")
		}
		ctx := context.Background()
		client, err := genai.NewClient(ctx, option.WithAPIKey(apiKey))
		if err != nil {
			log.Fatalf("Error creating AI client: %v", err)
		}
		defer client.Close()

		userInput := fmt.Sprintf("anggap dirimu adalah chef Berikan resep gampang dan berikan ukuran pasti tapi enak untuk: %s", req.FoodName+" di terakhir tuliskan by Chef SaveBite")

		model := client.GenerativeModel("gemini-1.5-flash")
		resp, err := model.GenerateContent(ctx, genai.Text(userInput))
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mendapatkan resep dari AI"})
			return
		}

		if len(resp.Candidates) == 0 || resp.Candidates[0].Content == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "AI tidak mengembalikan hasil yang valid"})
			return
		}

		var output strings.Builder
		for _, part := range resp.Candidates[0].Content.Parts {
			output.WriteString(fmt.Sprintf("%v\n", part))
		}

		foodID := 1 // Harus diambil dari food yang relevan
		err = AddFoodRecipe(foodID, output.String())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyimpan resep ke database"})
			return
		}

		c.JSON(http.StatusOK, RecipeResponse{Recipe: output.String()})
	})

	r.Run(":8080") // Jalankan server di port 8080
}
