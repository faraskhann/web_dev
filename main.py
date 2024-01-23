from web_dev import create_app

app = create_app()
if __name__ == "__main__":   # only runs the code if the file is run, not if it is imported.
    # without this it would just run when imported.
    app.run(debug=True)
