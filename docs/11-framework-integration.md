# ANDS Framework Integration Guide

Adding ANDS support to your AI system typically takes less than 60 seconds. You need to serve a static `ands.json` file at `/.well-known/ands.json`.

## 1. FastAPI (Python)

```python
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

app = FastAPI()

# Recommended: Serve via dedicated route
@app.get("/.well-known/ands.json")
async def get_ands_declaration():
    return FileResponse("ands.json")
```

## 2. Flask (Python)

```python
from flask import Flask, send_from_directory
import os

app = Flask(__name__)

@app.route('/.well-known/ands.json')
def serve_ands():
    return send_from_directory(os.path.join(app.root_path, '.well-known'),
                               'ands.json', mimetype='application/json')
```

## 3. Express.js (Node.js)

```javascript
const express = require('express');
const path = require('path');
const app = express();

// Option A: Static folder
app.use('/.well-known', express.static(path.join(__dirname, 'public/.well-known')));

// Option B: Dedicated route
app.get('/.well-known/ands.json', (req, res) => {
  res.sendFile(path.join(__dirname, 'ands.json'));
});
```

## 4. Nginx (Static)

If you are serving your API or documentation via Nginx:

```nginx
location /.well-known/ands.json {
    alias /var/www/html/metadata/ands.json;
    add_header Content-Type application/json;
    add_header Access-Control-Allow-Origin *;
}
```

## 5. Implementation Tips

- **CORS**: Always add `Access-Control-Allow-Origin: *` to your ANDS declaration to allow web-based auditors to fetch it.
- **Content-Type**: Ensure your server sends `application/json`.
- **Versioning**: If you update your system's capabilities, remember to update the ANDS code and re-sign the file.
