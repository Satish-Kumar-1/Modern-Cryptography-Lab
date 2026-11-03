import com.sun.net.httpserver.HttpServer;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.Executors;

/** Local-only static server and API proxy; no third-party libraries. */
class DevServer {
    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 5173;
        String backend = args.length > 1 ? args[1].replaceAll("/+$", "") : "http://127.0.0.1:8080";
        URI backendUri = URI.create(backend);
        if (!java.util.Set.of("http", "https").contains(backendUri.getScheme()) || backendUri.getHost() == null) throw new IllegalArgumentException("Backend must be an HTTP(S) URL");
        Path root = Path.of("").toAbsolutePath();
        Map<String, String> files = Map.of("/index.html", "text/html; charset=utf-8", "/styles.css", "text/css; charset=utf-8", "/api.js", "text/javascript; charset=utf-8", "/app.js", "text/javascript; charset=utf-8", "/math.js", "text/javascript; charset=utf-8", "/math-ui.js", "text/javascript; charset=utf-8", "/tests.html", "text/html; charset=utf-8", "/tests.js", "text/javascript; charset=utf-8");
        HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        server.createContext("/", exchange -> {
            int status = 200; byte[] body;
            try {
                String path = exchange.getRequestURI().getRawPath();
                if (path.equals("/api") || path.startsWith("/api/")) {
                    byte[] incoming = exchange.getRequestBody().readAllBytes();
                    HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(backend + exchange.getRequestURI().toASCIIString())).timeout(Duration.ofSeconds(9)).method(exchange.getRequestMethod(), incoming.length == 0 ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofByteArray(incoming));
                    for (String header : new String[]{"Content-Type", "Accept"}) { String value = exchange.getRequestHeaders().getFirst(header); if (value != null) request.header(header, value); }
                    HttpResponse<byte[]> response = client.send(request.build(), HttpResponse.BodyHandlers.ofByteArray());
                    status = response.statusCode(); body = response.body();
                    exchange.getResponseHeaders().set("Content-Type", response.headers().firstValue("Content-Type").orElse("application/json"));
                } else {
                    if (path.equals("/")) path = "/index.html";
                    if (!files.containsKey(path)) { status = 404; body = "Not found".getBytes(StandardCharsets.UTF_8); }
                    else if (!exchange.getRequestMethod().equals("GET") && !exchange.getRequestMethod().equals("HEAD")) { status = 405; body = new byte[0]; }
                    else { body = Files.readAllBytes(root.resolve(path.substring(1))); exchange.getResponseHeaders().set("Content-Type", files.get(path)); }
                }
            } catch (Exception error) {
                status = 502;
                body = "{\"detail\":\"Cannot reach the backend. Check that it is running.\"}".getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
            }
            exchange.getResponseHeaders().set("Cache-Control", "no-store");
            exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
            boolean noBody = exchange.getRequestMethod().equals("HEAD") || status == 204 || status == 304;
            exchange.sendResponseHeaders(status, noBody ? -1 : body.length);
            if (!noBody) exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        server.start();
        System.out.println("SignedChat: http://127.0.0.1:" + port);
        System.out.println("Backend: " + backend + " | Ctrl+C to stop");
    }
}
