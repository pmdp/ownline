from app import app

if __name__ == "__main__":
    # only run this in development, no at production!
    app.run()
else:
    print("uWSGI starting")
