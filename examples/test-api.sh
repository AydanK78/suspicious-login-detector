#!/bin/bash

# Test script for Suspicious Login Detector API
# Make sure the server is running (npm run dev) before running this script

API_URL="http://localhost:3000"

echo "Testing Suspicious Login Detector API"
echo "======================================"
echo ""

# Test 1: Health Check
echo "1. Health Check"
echo "---------------"
curl -s "${API_URL}/health" | python3 -m json.tool
echo ""
echo ""

# Test 2: Check a single login (normal)
echo "2. Check Single Login (Normal)"
echo "------------------------------"
curl -s -X POST "${API_URL}/api/login/check" \
  -H "Content-Type: application/json" \
  -d '{
    "userId": "test_user_1",
    "ipAddress": "8.8.8.8",
    "success": true,
    "timestamp": "2024-01-15T10:00:00Z"
  }' | python3 -m json.tool
echo ""
echo ""

# Test 3: Check another login from same user, same location
echo "3. Same User, Same Location (Low Risk)"
echo "---------------------------------------"
curl -s -X POST "${API_URL}/api/login/check" \
  -H "Content-Type: application/json" \
  -d '{
    "userId": "test_user_1",
    "ipAddress": "8.8.8.8",
    "success": true,
    "timestamp": "2024-01-16T10:00:00Z"
  }' | python3 -m json.tool
echo ""
echo ""

# Test 4: Check login with impossible travel
echo "4. Impossible Travel Detection"
echo "-------------------------------"
curl -s -X POST "${API_URL}/api/login/check" \
  -H "Content-Type: application/json" \
  -d '{
    "userId": "test_user_1",
    "ipAddress": "133.130.96.1",
    "success": true,
    "timestamp": "2024-01-16T10:30:00Z"
  }' | python3 -m json.tool
echo ""
echo ""

# Test 5: Failed login attempts (brute force)
echo "5. Simulating Brute Force Attack"
echo "---------------------------------"
for i in {1..5}; do
  curl -s -X POST "${API_URL}/api/login/check" \
    -H "Content-Type: application/json" \
    -d "{
      \"userId\": \"test_user_2\",
      \"ipAddress\": \"106.51.0.1\",
      \"success\": false,
      \"timestamp\": \"2024-01-17T14:0${i}:00Z\"
    }" > /dev/null
done

curl -s -X POST "${API_URL}/api/login/check" \
  -H "Content-Type: application/json" \
  -d '{
    "userId": "test_user_2",
    "ipAddress": "106.51.0.1",
    "success": true,
    "timestamp": "2024-01-17T14:10:00Z"
  }' | python3 -m json.tool
echo ""
echo ""

# Test 6: Batch analysis
echo "6. Batch Analysis"
echo "-----------------"
curl -s -X POST "${API_URL}/api/login/batch" \
  -H "Content-Type: application/json" \
  -d '{
    "attempts": [
      {
        "userId": "batch_user_1",
        "ipAddress": "8.8.8.8",
        "success": true,
        "timestamp": "2024-01-18T09:00:00Z"
      },
      {
        "userId": "batch_user_2",
        "ipAddress": "1.1.1.1",
        "success": true,
        "timestamp": "2024-01-18T10:00:00Z"
      }
    ]
  }' | python3 -m json.tool
echo ""
echo ""

# Test 7: Get user history
echo "7. Get User Login History"
echo "-------------------------"
curl -s "${API_URL}/api/user/test_user_1/history" | python3 -m json.tool
echo ""
echo ""

# Test 8: Get user risk profile
echo "8. Get User Risk Profile"
echo "------------------------"
curl -s "${API_URL}/api/user/test_user_1/risk-profile" | python3 -m json.tool
echo ""
echo ""

echo "======================================"
echo "API Testing Complete!"
echo "======================================"

