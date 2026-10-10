<?php
session_start();
require_once "db.php";

if (isset($_SESSION["user_id"], $_SESSION["role"])) {
    header("Location: " .
        ($_SESSION["role"] === "admin" ? "home2.php" : "home.php"));
    exit;
}

$error = "";
$success = "";
$page = $_GET["page"] ?? "login";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $action = $_POST["action"] ?? "";

    // =========================
    // REGISTRATION
    // =========================
    if ($action === "register") {
        $username = trim($_POST["username"] ?? "");
        $password = $_POST["password"] ?? "";
        $confirm = $_POST["confirm_password"] ?? "";
        $page = "register";

        if ($username === "" || $password === "" || $confirm === "") {
            $error = "All fields are required.";
        } elseif (!preg_match('/^[a-zA-Z0-9_]{3,50}$/', $username)) {
            $error = "Username must be 3-50 characters using letters, numbers, or underscores.";
        } elseif (strlen($password) < 8) {
            $error = "Password must be at least 8 characters.";
        } elseif ($password !== $confirm) {
            $error = "Passwords do not match.";
        } else {
            $check = $conn->prepare(
                "SELECT id FROM users WHERE username = ? LIMIT 1"
            );
            $check->bind_param("s", $username);
            $check->execute();
            $check->store_result();

            if ($check->num_rows > 0) {
                $error = "Username already exists.";
            } else {
                $hashedPassword = password_hash(
                    $password,
                    PASSWORD_DEFAULT
                );

                // Public registration always creates a regular user.
                $stmt = $conn->prepare(
                    "INSERT INTO users (username, password, role)
                     VALUES (?, ?, 'user')"
                );
                $stmt->bind_param("ss", $username, $hashedPassword);

                if ($stmt->execute()) {
                    $success = "Registration successful. You can now log in.";
                    $page = "login";
                } else {
                    $error = "Registration failed. Please try again.";
                }

                $stmt->close();
            }

            $check->close();
        }

    // =========================
    // LOGIN
    // =========================
    } elseif ($action === "login") {
        $username = trim($_POST["username"] ?? "");
        $password = $_POST["password"] ?? "";
        $page = "login";

        if ($username === "" || $password === "") {
            $error = "Please fill in all fields.";
        } else {
            $stmt = $conn->prepare(
                "SELECT id, username, password, role
                 FROM users
                 WHERE username = ?
                 LIMIT 1"
            );
            $stmt->bind_param("s", $username);
            $stmt->execute();

            $result = $stmt->get_result();
            $user = $result->fetch_assoc();

            if ($user && password_verify($password, $user["password"])) {
                session_regenerate_id(true);

                $_SESSION["user_id"] = $user["id"];
                $_SESSION["username"] = $user["username"];
                $_SESSION["role"] = $user["role"];

                header("Location: " .
                    ($user["role"] === "admin" ? "home2.php" : "home.php"));
                exit;
            } else {
                $error = "Invalid username or password.";
            }

            $stmt->close();
        }
    } else {
        $error = "Invalid request.";
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= $page === "register" ? "Create account" : "Log in" ?></title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Baloo+2:wght@600;800&family=Nunito:wght@400;700;800&display=swap">
    <link rel="stylesheet" href="assets/style.css">
</head>
<body>
<main class="auth">
    <section class="auth-brand">
        <img src="assets/logo.svg" alt="Jollibee">
        <p class="tag">Bida ang saya!</p>
    </section>

    <section class="auth-form">
        <div class="panel">

            <?php if ($error !== ""): ?>
                <div class="alert error" role="alert"><?= htmlspecialchars($error, ENT_QUOTES, "UTF-8") ?></div>
            <?php endif; ?>
            <?php if ($success !== ""): ?>
                <div class="alert success" role="status"><?= htmlspecialchars($success, ENT_QUOTES, "UTF-8") ?></div>
            <?php endif; ?>

            <?php if ($page === "register"): ?>

                <h1>Create account</h1>
                <p class="sub">It takes less than a minute.</p>

                <form method="POST" action="index.php?page=register">
                    <input type="hidden" name="action" value="register">

                    <label for="username">Username <span class="hint">(letters, numbers, underscores)</span></label>
                    <input id="username" type="text" name="username" minlength="3" maxlength="50"
                           autocomplete="username" required>

                    <label for="password">Password <span class="hint">(8+ characters)</span></label>
                    <input id="password" type="password" name="password" minlength="8"
                           autocomplete="new-password" required>

                    <label for="confirm">Confirm password</label>
                    <input id="confirm" type="password" name="confirm_password" minlength="8"
                           autocomplete="new-password" required>

                    <button class="btn" type="submit">Create account</button>
                </form>

                <p class="switch">Already have an account? <a href="index.php">Log in</a></p>

            <?php else: ?>

                <h1>Log in</h1>
                <p class="sub">Enter your username and password.</p>

                <form method="POST" action="index.php">
                    <input type="hidden" name="action" value="login">

                    <label for="username">Username</label>
                    <input id="username" type="text" name="username" maxlength="50"
                           autocomplete="username" required autofocus>

                    <label for="password">Password</label>
                    <input id="password" type="password" name="password"
                           autocomplete="current-password" required>

                    <button class="btn" type="submit">Log in</button>
                </form>

                <p class="switch">New here? <a href="index.php?page=register">Create an account</a></p>

            <?php endif; ?>

        </div>
    </section>
</main>
</body>
</html>
