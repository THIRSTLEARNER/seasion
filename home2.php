<?php
session_start();

if (!isset($_SESSION["user_id"], $_SESSION["role"])) {
    header("Location: index.php");
    exit;
}

if ($_SESSION["role"] !== "admin") {
    header("Location: home.php");
    exit;
}

if (isset($_GET["logout"])) {
    $_SESSION = [];
    session_destroy();
    header("Location: index.php");
    exit;
}

$username = htmlspecialchars($_SESSION["username"], ENT_QUOTES, "UTF-8");
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Admin dashboard</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Baloo+2:wght@600;800&family=Nunito:wght@400;700;800&display=swap">
        <link rel="stylesheet" href="assets/style.css">
</head>
<body>
<header class="topbar">
    <img src="assets/logo.svg" alt="Jollibee">
    <a class="logout" href="home2.php?logout=1">Log out</a>
</header>

<main class="home">
    <h1>Kumusta, <?= $username ?>!</h1>
    <span class="badge admin">admin</span>

    <section class="card">
        <h2>Admin dashboard</h2>
        <p>Only administrators can see this page.</p>
    </section>
</main>
</body>
</html>
