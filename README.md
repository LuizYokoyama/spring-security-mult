# Spring Security Multiple Authentication

Para testar:

curl -i http://localhost:8080/api/ping   --user "user1:pass"

curl -i http://localhost:8080/api/ping   -H "Accept: application/json"  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0LnRlc3QudGVzdCIsIm5hbWUiOiJhbnRvbmlvIiwiYXVkIjoidGFtYXJhIiwiaWF0IjoxNjg5MzY1MDM3LCJwcm9wWSI6dHJ1ZX0.CE5rMOOFut4SVVzuiBzwcQtL5tqSSkYI5lRIM9lXj6WY5GF4mhvz13S77wu6TRaQgdrwkBO8ltHvXPlslN4PcdcKbl098iN6pkGt2DUoiV0gv5MTnIbaYzpOgt7Wco3mi0ye-5MCeoWISkXYd63ECVR1dWdHVlihNPF28eIwRaONKC4iSWfdGDWC7T4H4a-zfa6R_vW4e3ZUztfGuLKtNqN8ypz6aAeGwO1c2Wyq4Le6cY7RSpJvnjopATA6FoqRafwc0v8JGHOkaD-mMQUjkxlMBsgNTtG22EjerM2YC2hPHAm4dbyTvrUM9nm_71nBFik66kXu1f10PL5dIna_OA"
