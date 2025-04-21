package db

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

// Structs for request/response
type Food struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	ExpiryDate string `json:"expiry_date"`
}

type AddFoodRequest struct {
	Name       string `json:"name"`
	ExpiryDate string `json:"expiry_date"`
}

type RecipeRequest struct {
	FoodID int `json:"food_id"`
}

type RecipeResponse struct {
	Recipe string `json:"recipe"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// Inisialisasi database
func InitDB() {
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		log.Fatal("DATABASE_URL environment variable is not set")
	}

	var err error
	DB, err = sql.Open("mysql", databaseURL)
	if err != nil {
		log.Fatalf("Gagal terhubung ke database: %v", err)
	}

	err = DB.Ping()
	if err != nil {
		log.Fatalf("Tidak bisa terhubung ke database: %v", err)
	}

	fmt.Println("✅ Berhasil terhubung ke database")
}

// Fungsi untuk menambah makanan
func AddFood(name, expiryDate, userId string) error {
	_, err := DB.Exec("INSERT INTO foods (name, expiry_date, user_id) VALUES (?, ?, ?)", name, expiryDate, userId)
	return err
}

// Function to generate JWT token
func GenerateJWT(username string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour) // Set token expiration to 24 hours
	claims := &Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(), // Set expiration time
			Issuer:    "myapp",               // Issuer of the token
		},
	}

	// Create new JWT token with claims and signing method
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Sign the token with the secret key
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// Fungsi untuk mendapatkan makanan berdasarkan user
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

// Fungsi untuk menambah resep makanan
func AddFoodRecipe(foodID int, recipe, userId string) error {
	_, err := DB.Exec("INSERT INTO food_recipes (food_id, recipe, user_id) VALUES (?, ?, ?)", foodID, recipe, userId)
	return err
}

// Fungsi untuk mendapatkan resep makanan
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

// Fungsi untuk menghasilkan resep menggunakan AI
func GenerateRecipe(foodName string) (string, error) {
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

	userInput := fmt.Sprintf("anggap dirimu adalah chef. Berikan resep gampang dan berikan ukuran pasti tapi enak untuk: %s. Di terakhir tuliskan by Chef SaveBite", foodName)
	model := client.GenerativeModel("gemini-1.5-flash")
	resp, err := model.GenerateContent(ctx, genai.Text(userInput))
	if err != nil {
		return "", err
	}

	if len(resp.Candidates) == 0 || resp.Candidates[0].Content == nil {
		return "", fmt.Errorf("AI tidak mengembalikan hasil yang valid")
	}

	var output strings.Builder
	for _, part := range resp.Candidates[0].Content.Parts {
		output.WriteString(fmt.Sprintf("%v\n", part))
	}

	return output.String(), nil
}

// Fungsi untuk validasi JWT token
func ValidateToken(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		c.JSON(401, gin.H{"error": "Token tidak ditemukan"})
		c.Abort()
		return
	}

	tokenString = tokenString[7:] // Menghapus "Bearer " dari token

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

		var userId, role string
		err := DB.QueryRow("SELECT id, role FROM users WHERE username = ?", claims.Username).Scan(&userId, &role)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
			c.Abort()
			return
		}

		c.Set("user_id", userId)
		c.Set("role", role)
		c.Next()
	} else {
		c.JSON(401, gin.H{"error": "Invalid token"})
		c.Abort()
	}
}

// Fungsi untuk melakukan login
func LoginHandler(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	var storedPasswordHash string
	err := DB.QueryRow("SELECT password FROM users WHERE username = ?", req.Username).Scan(&storedPasswordHash)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedPasswordHash), []byte(req.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	token, err := GenerateJWT(req.Username)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(200, gin.H{"token": token})
}

// Fungsi untuk melakukan registrasi
func RegisterHandler(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if req.Role != "user" && req.Role != "admin" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Role must be 'admin' or 'user'"})
		return
	}

	var existingUsername string
	err := DB.QueryRow("SELECT username FROM users WHERE username = ?", req.Username).Scan(&existingUsername)
	if err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
		return
	}

	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

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

// Fungsi untuk mendapatkan nama makanan berdasarkan ID
func GetFoodName(foodID int, userId string) (string, error) {
	var foodName string
	err := DB.QueryRow("SELECT name FROM foods WHERE id = ? AND user_id = ?", foodID, userId).Scan(&foodName)
	if err != nil {
		return "", err
	}
	return foodName, nil
}
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
