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
var jwtSecret = []byte("your_secret_key")

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
	ID     int    `json:"id"`
	FoodID int    `json:"food_id"`
	Recipe string `json:"recipe"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

type LoginLog struct {
	ID        int
	UserID    int
	Username  string
	LoginTime string
	IPAddress string
}

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

func GetLoginLogs(userId string) ([]LoginLog, error) {

	rows, err := DB.Query("SELECT id, user_id, username, login_time, ip_address FROM login_logs ORDER BY login_time DESC")
	if err != nil {

		return nil, fmt.Errorf("gagal menjalankan query: %v", err)
	}
	defer rows.Close()

	var logs []LoginLog

	for rows.Next() {
		var logEntry LoginLog

		if err := rows.Scan(&logEntry.ID, &logEntry.UserID, &logEntry.Username, &logEntry.LoginTime, &logEntry.IPAddress); err != nil {

			return nil, fmt.Errorf("gagal melakukan scan baris: %v", err)
		}
		logs = append(logs, logEntry)
	}

	if err := rows.Err(); err != nil {

		return nil, fmt.Errorf("terjadi kesalahan saat iterasi: %v", err)
	}

	return logs, nil
}

func AddFood(name, expiryDate, userId string) error {
	_, err := DB.Exec("INSERT INTO foods (name, expiry_date, user_id) VALUES (?, ?, ?)", name, expiryDate, userId)
	return err
}

func GenerateJWT(username string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
			Issuer:    "myapp",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

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

func AddFoodRecipe(foodID int, recipe, userId string) error {
	_, err := DB.Exec("INSERT INTO food_recipes (food_id, recipe, user_id) VALUES (?, ?, ?)", foodID, recipe, userId)
	return err
}

func GetFoodRecipes(userId string) ([]RecipeResponse, error) {

	rows, err := DB.Query("SELECT id, food_id, recipe FROM food_recipes WHERE user_id = ?", userId)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var recipes []RecipeResponse

	for rows.Next() {
		var recipeResponse RecipeResponse
		if err := rows.Scan(&recipeResponse.ID, &recipeResponse.FoodID, &recipeResponse.Recipe); err != nil {
			return nil, err
		}
		recipes = append(recipes, recipeResponse)
	}

	return recipes, nil
}
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

func ValidateToken(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		c.JSON(401, gin.H{"error": "Token tidak ditemukan"})
		c.Abort()
		return
	}

	tokenString = tokenString[7:]

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

func SaveLoginLog(userId, username, ipAddress string) error {

	loginTime := time.Now().UTC()

	_, err := DB.Exec("INSERT INTO login_logs (user_id, username, ip_address, login_time) VALUES (?, ?, ?, ?)", userId, username, ipAddress, loginTime)
	if err != nil {
		log.Printf("Error saving login log: %v", err)
		return err
	}
	return nil
}

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
	var userId string
	err := DB.QueryRow("SELECT id, password FROM users WHERE username = ?", req.Username).Scan(&userId, &storedPasswordHash)
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

	ipAddress := c.ClientIP()

	err = SaveLoginLog(userId, req.Username, ipAddress)
	if err != nil {
		log.Printf("Gagal menyimpan log login: %v", err)
	}

	c.JSON(200, gin.H{"token": token})
}

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

func hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

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
		log.Printf("Error executing query: %v", err)
		return nil, err
	}
	defer rows.Close()

	var users []map[string]interface{}
	for rows.Next() {
		var userId, username, role string
		if err := rows.Scan(&userId, &username, &role); err != nil {
			log.Printf("Error scanning row: %v", err)
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
		log.Printf("Error iterating over rows: %v", err) 
		return nil, err
	}

	return users, nil
}
