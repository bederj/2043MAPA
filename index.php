<?php
    require("config.php"); // linked to config page
    $submitted_username = '';
    if(!empty($_POST)){
        $query = "CALL selectUser(?)";

        try{
            $stmt = $db->prepare($query);
            $stmt->bindParam(1, $_POST['username'] , PDO::PARAM_STR|PDO::PARAM_INPUT_OUTPUT, 4000);
            $result = $stmt->execute(); // selects user from user database
        }
        catch(PDOException $ex){ die("Failed to run query: " . $ex->getMessage()); } // presents error if quiery cannot be run
        $login_ok = false;
        $row = $stmt->fetch(); // fetch results from quiery
        if($row){
            $check_password = hash('sha256', $_POST['password'] . $row['salt']);
            for($round = 0; $round < 65536; $round++){
                $check_password = hash('sha256', $check_password . $row['salt']);
            } // salting and hashing password to ensure uniqueness and to avoid reversing encryption
            if($check_password === $row['password']){
                $login_ok = true;
            } // checking if password correct and matches the pne sorted in the database.
        }

        if($login_ok){
            unset($row['salt']); //remove password from session
            unset($row['password']); //remove password from session
            $_SESSION['user'] = $row;
            header("Location: secret.php"); // redirected to content hiden by password
            die("Redirecting to: secret.php");
        }
        else{
            print("Login Failed.");
            $submitted_username = htmlentities($_POST['username'], ENT_QUOTES, 'UTF-8');
        }
    }
?>
<!DOCTYPE html>
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
            <h1 class="form-signin-heading">Login</h1>
            <form class="form-signin" action="index.php" method="post">
            <div class="form-group">
              <input type="text" placeholder="Username" name="username" class="form-control" value=""/>
            </div>
            <div class="form-group">
              <input type="password" placeholder="Password" name="password" value="" class="form-control">
            </div>
            <input type="submit" class="btn btn-success" value="Login" />
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
