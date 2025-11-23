$baseUrl = "http://localhost:3000"
$username = "testuser"
$password = "password123"

Write-Host "1. Testing Unprotected Access to /api/stats (Expect 401)..."
try {
    $response = Invoke-RestMethod -Uri "$baseUrl/api/stats" -Method Get -ErrorAction Stop
    Write-Host "FAILED: Should have been 401" -ForegroundColor Red
} catch {
    if ($_.Exception.Response.StatusCode -eq [System.Net.HttpStatusCode]::Unauthorized) {
        Write-Host "PASSED: Got 401 Unauthorized" -ForegroundColor Green
    } else {
        Write-Host "FAILED: Got $($_.Exception.Response.StatusCode)" -ForegroundColor Red
    }
}

Write-Host "`n2. Registering User..."
try {
    $body = @{ username = $username; password = $password } | ConvertTo-Json
    $response = Invoke-RestMethod -Uri "$baseUrl/api/auth/register" -Method Post -Body $body -ContentType "application/json"
    Write-Host "PASSED: User registered" -ForegroundColor Green
} catch {
    Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`n3. Logging In..."
$token = $null
try {
    $body = @{ username = $username; password = $password } | ConvertTo-Json
    $response = Invoke-RestMethod -Uri "$baseUrl/api/auth/login" -Method Post -Body $body -ContentType "application/json"
    $token = $response.accessToken
    if ($token) {
        Write-Host "PASSED: Got Token" -ForegroundColor Green
    } else {
        Write-Host "FAILED: No token in response" -ForegroundColor Red
    }
} catch {
    Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
}

if ($token) {
    Write-Host "`n4. Testing Protected Access with Token..."
    try {
        $headers = @{ Authorization = "Bearer $token" }
        $response = Invoke-RestMethod -Uri "$baseUrl/api/stats" -Method Get -Headers $headers
        Write-Host "PASSED: Got Stats" -ForegroundColor Green
    } catch {
        Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
    }
}
