from fastapi import FastAPI

app = FastAPI(
    title="Sentinel API",
    description="Security event monitroing tools",
    version="0.1.0"
)

@app.get("/health")
def health():
    return {"status":"ok"}

@app.get("/v1/models")
def list_models():
    return{
        "object":"list",
        "data":[
            {
                "id":"sentinel-model",
                "object":"model",
               "owned_by":"sentinel",
            }
        ],
    }