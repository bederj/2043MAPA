<?php
    require("config.php");
    if(!empty($_POST))
    {
        // Ensure that the user fills out fields
        if(empty($_POST['username']))
        { die("Please enter a username."); }
        if(empty($_POST['password']))
        { die("Please enter a password."); }
        if(!filter_var($_POST['email'], FILTER_VALIDATE_EMAIL))
        { die("Invalid E-Mail Address"); }

        // Check if the username is already taken
        $query = "CALL selectUser(?)";

        try {
            $stmt = $db->prepare($query);
			 $stmt->bindParam(1, $_POST['username'] , PDO::PARAM_STR|PDO::PARAM_INPUT_OUTPUT, 4000);
            $result = $stmt->execute(); // selects user from user database
        }
        catch(PDOException $ex){ die("Failed to run query: " . $ex->getMessage()); }
        $row = $stmt->fetch(); // presents error if quiery cannot be run
        if($row){ die("This username is already in use"); }
        $query = "CALL selectEmail(?)";

        try {
            $stmt = $db->prepare($query);
			$stmt->bindParam(1, $_POST['email'] , PDO::PARAM_STR|PDO::PARAM_INPUT_OUTPUT, 4000);
            $result = $stmt->execute(); // selects email from database
        }
        catch(PDOException $ex){ die("Failed to run query: " . $ex->getMessage());}
        $row = $stmt->fetch();
        if($row){ die("This email address is already registered"); }

        // Add row to database
        $query = "CALL insertUser(?,?,?,?)";

        // Security measures
        $salt = dechex(mt_rand(0, 2147483647)) . dechex(mt_rand(0, 2147483647));
        $password = hash('sha256', $_POST['password'] . $salt);
        for($round = 0; $round < 65536; $round++){ $password = hash('sha256', $password . $salt); } // salting and hashing password to ensure uniqueness and to avoid reversing encryption

        try {
            $stmt = $db->prepare($query);
			$stmt->bindParam(1, $_POST['username'] , PDO::PARAM_STR|PDO::PARAM_INPUT_OUTPUT, 4000);
			$stmt->bindParam(2, $password , PDO::PARAM_STR|PDO::PARAM_INPUT_OUTPUT, 4000);
			$stmt->bindParam(3, $salt , PDO::PARAM_STR|PDO::PARAM_INPUT_OUTPUT, 4000);
			$stmt->bindParam(4, $_POST['email'] , PDO::PARAM_STR|PDO::PARAM_INPUT_OUTPUT, 4000);
            $result = $stmt->execute();
            // storing user in databse
        }
        catch(PDOException $ex){ die("Failed to run query: " . $ex->getMessage()); }
        header("Location: index.php");
        die("Redirecting to index.php");
    }
?>


 <!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="">
    <meta name="author" content="">
    <link rel="icon" href="../../../../favicon.ico">

    <title>Cover Template for Bootstrap</title>

    <!-- Bootstrap core CSS -->
    <link href="css/bootstrap.min.css" rel="stylesheet">

    <!-- Custom styles for this template -->
    <link href="css/style.css" rel="stylesheet">
  </head>

  <body>

    <div class="site-wrapper">

      <div class="site-wrapper-inner">

        <div class="cover-container">

          <header class="masthead clearfix">
            <div class="inner">
              <h3 class="masthead-brand">Cover</h3>
              <nav class="nav nav-masthead">
                <a class="nav-link active" href="index.php">Home</a>
                <a class="nav-link" href="register.php">Register</a>

              </nav>
            </div>
          </header>

          <main role="main" class="inner cover">
        <h1 class="form-signin-heading">Register</h1>
        <form class="form-signin" action="register.php" method="post">
        <br>
        <input class="form-control" placeholder="Username" type="text" name="username" value="" />
        <br>
        <input class="form-control" placeholder="Email" type="text" name="email" value="" />
        <br>
        <input class="form-control" placeholder="Password" type="password" name="password" value="" />
        <br>
        <input type="submit" class="btn btn-info" value="Register" />
    </form>
          </main>

          <footer class="mastfoot">
            <div class="inner">
              <p>Cover template for <a href="https://getbootstrap.com/">Bootstrap</a>, by <a href="https://twitter.com/mdo">@mdo</a>.</p>
            </div>
          </footer>

        </div>

      </div>

    </div>

    <!-- Bootstrap core JavaScript
    ================================================== -->
    <!-- Placed at the end of the document so the pages load faster -->
    <script src="https://code.jquery.com/jquery-3.2.1.slim.min.js" integrity="sha384-KJ3o2DKtIkvYIK3UENzmM7KCkRr/rE9/Qpg6aAZGJwFDMVNA/GpGFF93hXpG5KkN" crossorigin="anonymous"></script>
   <script src="js/bootstrap.min.js"></script>
  </body>
</html>
