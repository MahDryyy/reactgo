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
	"github.com/joho/godotenv"
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
	FoodID int `json:"food_id"`
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
	// Memuat file .env
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	// Mengambil informasi URL koneksi database dari variabel lingkungan
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("DATABASE_URL environment variable is not set")
	}

	var err error
	DB, err = sql.Open("mysql", databaseURL) // Menggunakan DATABASE_URL dari .env
	if err != nil {
		log.Fatalf("Gagal terhubung ke database: %v", err)
	}

	// Verifikasi koneksi ke database
	err = DB.Ping()
	if err != nil {
		log.Fatalf("Tidak bisa terhubung ke database: %v", err)
	}

	fmt.Println("✅ Berhasil terhubung ke database")
}

// Fungsi untuk menambah makanan ke database
func AddFood(name, expiryDate, userId string) error {
	_, err := DB.Exec("INSERT INTO foods (name, expiry_date, user_id) VALUES (?, ?, ?)", name, expiryDate, userId)
	return err
}

// Fungsi untuk mengambil semua makanan dari database berdasarkan user_id
func GetFoods(userId string) ([]Food, error) {
	rows, err := DB.Query("SELECT id, name, expiry_date FROM foods WHERE user_id = ?", userId)
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

// Fungsi untuk menambah resep makanan ke database
func AddFoodRecipe(foodID int, recipe, userId string) error {
	_, err := DB.Exec("INSERT INTO food_recipes (food_id, recipe, user_id) VALUES (?, ?, ?)", foodID, recipe, userId)
	return err
}

// Fungsi untuk mengambil resep makanan berdasarkan user_id
func GetFoodRecipes(userId string) ([]string, error) {
	rows, err := DB.Query("SELECT recipe FROM food_recipes WHERE user_id = ?", userId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var recipes []string
	for rows.Next() {
		var recipe string
		if err := rows.Scan(&recipe); err != nil {
			return nil, err
		}
		recipes = append(recipes, recipe)
	}

	return recipes, nil
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

	tokenString = tokenString[7:] // Remove "Bearer " prefix

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("invalid signing method")
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		c.JSON(401, gin.H{"error": "Invalid token"})
		c.Abort()
		return
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		c.Set("username", claims.Username)

		// Fetch user info from DB (id, role)
		var userId, role string
		err := DB.QueryRow("SELECT id, role FROM users WHERE username = ?", claims.Username).Scan(&userId, &role)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
			c.Abort()
			return
		}

		// Store user_id and role in context
		c.Set("user_id", userId)
		c.Set("role", role)
		c.Next()
	} else {
		c.JSON(401, gin.H{"error": "Invalid token"})
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

// Fungsi untuk mengambil semua pengguna dari database
func GetUsers() ([]map[string]interface{}, error) {
	rows, err := DB.Query("SELECT id, username, role FROM users")
	if err != nil {
		log.Printf("Error executing query: %v", err) // Log the error for debugging
		return nil, err
	}
	defer rows.Close()

	var users []map[string]interface{}
	for rows.Next() {
		var userId, username, role string
		if err := rows.Scan(&userId, &username, &role); err != nil {
			log.Printf("Error scanning row: %v", err) // Log scanning error
			return nil, err
		}
		user := map[string]interface{}{
			"id":       userId,
			"username": username,
			"role":     role,
		}
		users = append(users, user)
	}

	if err := rows.Err(); err != nil {
		log.Printf("Error iterating over rows: %v", err) // Log iteration error
		return nil, err
	}

	return users, nil
}

// Fungsi untuk hash password
func hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// Route utama
func main() {
	// Inisialisasi database
	InitDB()

	r := gin.Default()

	// Route untuk register pengguna baru
	r.POST("/register", registerHandler)

	// Route untuk login pengguna
	r.POST("/login", loginHandler)
	// Endpoint untuk melihat semua resep yang dimiliki oleh pengguna
	r.GET("/recipes", ValidateToken, func(c *gin.Context) {
		// Mendapatkan user_id dari context
		userId := c.MustGet("user_id").(string)

		// Mengambil resep yang dimiliki oleh pengguna yang sedang login
		recipes, err := GetFoodRecipes(userId)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil resep"})
			return
		}

		// Jika tidak ada resep ditemukan
		if len(recipes) == 0 {
			c.JSON(http.StatusOK, gin.H{"message": "Tidak ada resep yang ditemukan"})
			return
		}

		// Mengirimkan daftar resep yang dimiliki oleh pengguna
		c.JSON(http.StatusOK, gin.H{"recipes": recipes})
	})
	// Endpoint untuk melihat daftar pengguna
	r.GET("/users", ValidateToken, func(c *gin.Context) {
		// Mengambil role dari context
		role := c.MustGet("role").(string)

		// Memastikan hanya admin yang bisa mengakses endpoint ini
		if role != "admin" {
			c.JSON(http.StatusForbidden, gin.H{"error": "Anda tidak memiliki izin untuk mengakses daftar pengguna"})
			return
		}

		// Mengambil daftar pengguna dari database
		users, err := GetUsers()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil data pengguna"})
			return
		}

		// Mengirimkan daftar pengguna
		c.JSON(http.StatusOK, gin.H{"users": users})
	})

	// Admin/User: Bisa menambah makanan
	r.POST("/foods", ValidateToken, func(c *gin.Context) {
		var req AddFoodRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Format request salah"})
			return
		}

		userId := c.MustGet("user_id").(string)
		err := AddFood(req.Name, req.ExpiryDate, userId)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyimpan makanan"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Makanan berhasil disimpan"})
	})

	// Admin/User: Bisa menghapus makanan
	r.DELETE("/foods/:id", ValidateToken, func(c *gin.Context) {
		id := c.Param("id")
		userId := c.MustGet("user_id").(string)

		// Pastikan makanan ini milik user yang login
		var foodUserId string
		err := DB.QueryRow("SELECT user_id FROM foods WHERE id = ?", id).Scan(&foodUserId)
		if err != nil || foodUserId != userId {
			c.JSON(http.StatusForbidden, gin.H{"error": "Makanan tidak ditemukan atau tidak milik Anda"})
			return
		}

		// Hapus makanan
		_, err = DB.Exec("DELETE FROM foods WHERE id = ?", id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menghapus makanan"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Makanan berhasil dihapus"})
	})

	// User: Bisa melihat makanan
	r.GET("/foods", ValidateToken, func(c *gin.Context) {
		userId := c.MustGet("user_id").(string)

		// Ambil makanan yang dimiliki oleh pengguna yang sedang login
		foods, err := GetFoods(userId)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengambil data makanan"})
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

		// Mendapatkan user_id dari context
		userId := c.MustGet("user_id").(string)

		// Validasi ID makanan yang dipilih, pastikan makanan tersebut milik user yang sedang login
		var foodName string
		err := DB.QueryRow("SELECT name FROM foods WHERE id = ? AND user_id = ?", req.FoodID, userId).Scan(&foodName)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Makanan tidak ditemukan atau tidak milik Anda"})
			return
		}

		// Membuat prompt AI untuk resep
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

		// Membuat prompt AI berdasarkan nama makanan yang dipilih
		userInput := fmt.Sprintf("anggap dirimu adalah chef. Berikan resep gampang dan berikan ukuran pasti tapi enak untuk: %s. Di terakhir tuliskan by Chef SaveBite", foodName)

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

		// Menyimpan resep ke database untuk makanan yang relevan
		var output strings.Builder
		for _, part := range resp.Candidates[0].Content.Parts {
			output.WriteString(fmt.Sprintf("%v\n", part))
		}

		err = AddFoodRecipe(req.FoodID, output.String(), userId)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyimpan resep ke database"})
			return
		}

		// Mengirimkan resep yang dihasilkan ke pengguna
		c.JSON(http.StatusOK, RecipeResponse{Recipe: output.String()})
	})

	r.Run(":8080") // Jalankan server di port 8080
}
