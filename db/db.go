package db

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode"

	"database/sql"

	"github.com/gin-gonic/gin"
	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v4"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
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
	FoodID []int `json:"food_id"`
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

func AddFoodRecipe(recipe, userId string) error {
	{
		_, err := DB.Exec("INSERT INTO food_recipes (food_id, recipe, user_id) VALUES (?, ?, ?)", recipe, userId)
		if err != nil {
			return err
		}
	}
	return nil
}

func GetFoodRecipes(userId string) ([]RecipeResponse, error) {

	rows, err := DB.Query("SELECT id, recipe FROM food_recipes WHERE user_id = ?", userId)
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

	var storedPasswordHash, userRole string
	var userId string
	err := DB.QueryRow("SELECT id, password, role FROM users WHERE username = ?", req.Username).Scan(&userId, &storedPasswordHash, &userRole)
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

	c.JSON(200, gin.H{
		"token": token,
		"role":  userRole,
	})
}

func isValidEmail(email string) bool {

	re := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	return re.MatchString(email)
}

func isValidPassword(password string) bool {
	if len(password) < 8 {
		return false
	}

	var hasUpper, hasSymbol bool

	for _, char := range password {
		if unicode.IsUpper(char) {
			hasUpper = true
		} else if strings.ContainsRune("!@#$%^&*()_+{}[]:;<>,.?/~`-=", char) {
			hasSymbol = true
		}
	}

	return hasUpper && hasSymbol
}

func RegisterHandler(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Email    string `json:"email"`
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

	if !isValidEmail(req.Email) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
		return
	}

	if !isValidPassword(req.Password) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password must be at least 8 characters long, contain an uppercase letter and a symbol"})
		return
	}

	var existingEmail string
	err := DB.QueryRow("SELECT email FROM users WHERE email = ?", req.Email).Scan(&existingEmail)
	if err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Email already exists"})
		return
	}

	var existingUsername string
	err = DB.QueryRow("SELECT username FROM users WHERE username = ?", req.Username).Scan(&existingUsername)
	if err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
		return
	}

	hashedPassword, err := hashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	_, err = DB.Exec("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)", req.Username, hashedPassword, req.Email, req.Role)
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
