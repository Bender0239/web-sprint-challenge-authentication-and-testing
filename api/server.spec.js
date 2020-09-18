const supertest = require("supertest")
const db = require("../database/dbConfig")
const server = require("./server")





describe("jokes router", () => {
    it("doesnt pass", () => {
        supertest(server).get('/api/jokes')
        .expect(401)
    })
    it("doesnt pass", async () => {
        const res = await supertest(server).get('/api/jokes')
            expect(res.body.message).toBe("Invalid credentials")
            
    })
})

describe("post user", () => {
    beforeEach(async () => {
        // trucate or empty the hobbits table
        await db("users").truncate();
    });
    it("should allow signup", () => {
        supertest(server)
        .post("/api/auth/register")
        .send({
            username: "tippy1",
            password: "yungtipper"
        })
        .then(res => {
            expect(res.status).toBe(201)
        })
    })
    it("should not allow signup", () => {
        supertest(server)
        .post("/api/auth/register")
        .send({})
        .then(res => {
            expect(res.status).toBe(500)
        })
    })
})

describe("login user", () => {
    it("should login user", () => {
        supertest(server)
        .post("/api/auth/login")
        .send({
            username: "tippy1",
            password: "yungtipper"
        })
        .then(res => {
            expect(res.status).toBe(500)
        })
    })
    it("should not login user", () => {
        supertest(server)
        .post("/api/auth/login")
        .send({
            username: "",
            password: ""
        })
        .then(res => {
            expect(res.status).toBe(401)
        })
    })
})