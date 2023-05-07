package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Database instance and collection
var orderCollection *mongo.Collection
var userCollection *mongo.Collection
var ctx context.Context

// Order is the struct that represents an order
type Order struct {
	ID          primitive.ObjectID `json:"id,omitempty" bson:"_id,omitempty"`
	User        primitive.ObjectID `json:"user" bson:"user"`
	Origin      string             `json:"origin" bson:"origin"`
	Destination string             `json:"destination" bson:"destination"`
	Status      string             `json:"status" bson:"status"`
}

type User struct {
	ID       primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Name     string             `json:"name" bson:"name"`
	Email    string             `json:"email" bson:"email"`
	Phone    string             `json:"phone" bson:"phone"`
	Password string             `json:"password" bson:"password"`
}

func hashPassword(password string) string { // O(1)
	h := sha256.Sum256([]byte(password))
	return hex.EncodeToString(h[:])
}

func registerHandler(w http.ResponseWriter, r *http.Request) { //O(1)
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	user.Password = hashPassword(user.Password)
	_, err = userCollection.InsertOne(r.Context(), user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte("201 - Successfully Created"))
}

func loginHandler(w http.ResponseWriter, r *http.Request) { //O(1)
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	user.Password = hashPassword(user.Password)
	result := userCollection.FindOne(r.Context(), bson.M{"email": user.Email, "password": user.Password})
	if err := result.Err(); err != nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}
	var foundUser User
	err = result.Decode(&foundUser)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	user = foundUser

	claims := jwt.StandardClaims{
		Subject:   user.ID.Hex(),
		ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte("secret"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"token": tokenString,
	})
	//json.NewEncoder(w).Encode(foundUser)
}

// Auth Middleware to check JWT Token
var verifiedUser primitive.ObjectID

func authMiddleware(next http.HandlerFunc) http.HandlerFunc { //O(1)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header missing", http.StatusUnauthorized)
			return
		}
		tokenString := strings.ReplaceAll(authHeader, "Bearer ", "")
		token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return []byte("secret"), nil
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if claims, ok := token.Claims.(*jwt.StandardClaims); ok && token.Valid {
			userID, err := primitive.ObjectIDFromHex(claims.Subject)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			result := userCollection.FindOne(r.Context(), bson.M{"_id": userID})
			if err := result.Err(); err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			verifiedUser = userID
			next(w, r)
		} else {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
	})
}

// Create an order
func createOrder(response http.ResponseWriter, request *http.Request) { //O(1)
	response.Header().Set("content-type", "application/json")
	var order Order
	_ = json.NewDecoder(request.Body).Decode(&order)
	order.User = verifiedUser
	result, err := orderCollection.InsertOne(ctx, order)
	if err != nil {
		log.Fatal(err)
	}
	json.NewEncoder(response).Encode(result)
}

// Get all orders
func getAllOrders(response http.ResponseWriter, request *http.Request) { //O(n)
	response.Header().Set("content-type", "application/json")
	var orders []Order
	cursor, err := orderCollection.Find(ctx, bson.M{})
	if err != nil {
		log.Fatal(err)
	}
	defer cursor.Close(ctx)
	for cursor.Next(ctx) {
		var order Order
		cursor.Decode(&order)
		orders = append(orders, order)
	}
	if err := cursor.Err(); err != nil {
		log.Fatal(err)
	}
	json.NewEncoder(response).Encode(orders)
}

// Get an order by ID
func getOrder(response http.ResponseWriter, request *http.Request) { //O(1)
	response.Header().Set("content-type", "application/json")
	params := mux.Vars(request)
	id, _ := primitive.ObjectIDFromHex(params["id"])
	var order Order
	err := orderCollection.FindOne(ctx, bson.M{"_id": id}).Decode(&order)
	if err != nil {
		log.Fatal(err)
	}
	json.NewEncoder(response).Encode(order)
}

// Update an order by ID
func updateOrder(response http.ResponseWriter, request *http.Request) { //O(1)
	response.Header().Set("content-type", "application/json")
	params := mux.Vars(request)
	id, _ := primitive.ObjectIDFromHex(params["id"])
	var order Order
	_ = json.NewDecoder(request.Body).Decode(&order)
	order.ID = id
	if order.User != verifiedUser {
		http.Error(response, "Invalid user", http.StatusUnauthorized)
		return
	}
	result, err := orderCollection.ReplaceOne(ctx, bson.M{"_id": id}, order)
	if err != nil {
		log.Fatal(err)
	}
	json.NewEncoder(response).Encode(result)
}

func getMongoClient() (*mongo.Client, error) { //O(1)
	serverAPIOptions := options.ServerAPI(options.ServerAPIVersion1)
	clientOptions := options.Client().
		ApplyURI("mongodb+srv://haniif02aj:uQz7VLcY70SoS4JA@test.dkwiku6.mongodb.net/?retryWrites=true&w=majority").
		SetServerAPIOptions(serverAPIOptions)
	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		return nil, fmt.Errorf("error connecting to MongoDB: %s", err)
	}
	err = client.Ping(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("error pinging MongoDB: %s", err)
	}
	return client, nil
}

func main() {
	// Set up MongoDB connection
	client, err := getMongoClient()
	if err != nil {
		log.Fatal(err)
	}
	defer client.Disconnect(ctx)
	orderCollection = client.Database("studycase1").Collection("order")
	userCollection = client.Database("studycase1").Collection("user")
	// Set up router
	router := mux.NewRouter()

	// Define routes
	router.HandleFunc("/login", loginHandler).Methods("POST")
	router.HandleFunc("/register", registerHandler).Methods("POST")
	router.HandleFunc("/order", authMiddleware(createOrder)).Methods("POST")
	router.HandleFunc("/order", authMiddleware(getAllOrders)).Methods("GET")
	router.HandleFunc("/order/{id}", authMiddleware(getOrder)).Methods("GET")
	router.HandleFunc("/order/{id}", authMiddleware(updateOrder)).Methods("PUT")

	// Start server
	log.Fatal(http.ListenAndServe(":8080", router))
}
