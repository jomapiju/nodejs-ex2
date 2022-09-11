const express = require('express')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')

const knex = require('knex')({
    client: 'pg',
    debug: true,
    connection: {
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false },
    }
})

let apiRouter = express.Router()

const endpoint = '/'

let checkToken = (req, res, next) => {
    let authToken = req.headers["authorization"]
    if (!authToken) {
        res.status(401).json({ message: 'Token de acesso requerida' })
    } else {
        let token = authToken.split(' ')[1]
        req.token = token
    }

    jwt.verify(req.token, process.env.SECRET_KEY, (err, decodeToken) => {
        if(err) {
            res.status(401).json({ message: 'Acesso negado'})
            return
        }
        req.usuarioId = decodeToken.id
        next()
    })
}

let isAdmin = (req, res, next) => {
    knex
        .select('*').from('usuario').where({ id: req.usuarioId })
        .then(usuarios => {
            let usuario = usuarios[0]
            let roles = usuario.roles.split(';')
            let adminRole = roles.find(i => i === 'ADMIN')
            if (adminRole === 'ADMIN') {
                next()
                return
            } else {
                res.status(403).json({ message: 'Role de ADMIN requerida'})
                return
            }
        })
        .catch( err => {
            res.status(500).json({
                message: 'Erro ao verificar roles do usuario - ' + err.message
            })
        })
}

apiRouter.get(endpoint + 'produtos', /*checkToken,*/ (req, res) => {
    knex.select('*').from('produto')
    .then(produtos => res.status(200).json(produtos))
    .catch(err => {
        res.status(500).json({
            message: 'Erro ao recuperar produtos - ' + err.message })
    })
})

apiRouter.get(endpoint + 'produto/:id', /*checkToken,*/ (req, res) => {
    const {id} = req.params

    knex.where({id:id}).select('*').from('produto')
    .then(produto => res.status(200).json(produto))
    .catch(err => {
        res.status(500).json({
            message: 'Erro ao recuperar produtos - ' + err.message })
    })
})

apiRouter.post(endpoint + 'produto', /*checkToken, isAdmin,*/ (req, res) => {
    const { descricao, valor, marca } = req.body
    knex.insert({descricao,valor,marca}).table('produto').then(produto => {
        res.sendStatus(201)
    })
    .catch( err => {
        res.status(500).json({
            message: 'Erro ao inserir produto - ' + err.message
        })
    })
})

apiRouter.delete(endpoint+'produto/:id', /*checkToken, isAdmin,*/ (req, res) => {
    const {id} = req.params

    knex.where({id: id}).del().table('produto').then(() => {
        res.sendStatus(200)
    })
    .catch( err => {
        res.status(500).json({
            message: 'Erro ao removar produto - ' + err.message })
    })
})

apiRouter.put(endpoint+'produto/:id', /*checkToken, isAdmin,*/ (req, res) => {
    const { id } = req.params
    const { descricao, valor, marca } = req.body
    knex.where({id:id}).update({descricao,valor,marca}).table('produto').then(produto => {
        res.sendStatus(200)
    })
    .catch( err => {
        res.status(500).json({
            message: 'Erro ao atualizar produto - ' + err.message
        })
    })
})

apiRouter.post(endpoint + 'seguranca/registrar', (req, res) => {
    knex('usuario')
        .insert({
            nome: req.body.nome,
            login: req.body.login,
            senha: bcrypt.hashSync(req.body.senha, 8),
            email: req.body.email
        }, ['id'])
        .then(result => {
            let usuario = result[0]
            res.status(200).json({"id": usuario.id})
            return
        })
        .catch( err => {
            res.status(500).json({
                message: 'Erro ao registar usuario - ' + err.message
            })
        })
})

apiRouter.post(endpoint + 'seguranca/login', (req, res) => {
    knex
        .select('*').from('usuario').where({ login: req.body.login })
        .then(usuarios => {
            if(usuarios.length) {
                let usuario = usuarios[0]
                let checkSenha = bcrypt.compareSync(req.body.senha, usuario.senha)
                if (checkSenha) {
                    var tokenJWT = jwt.sign({ id: usuario.id },
                        process.env.SECRET_KEY, {
                            expiresIn: 3600,
                        })
                    res.status(200).json({
                        id: usuario.id,
                        login: usuario.login,
                        nome: usuario.nome,
                        roles: usuario.roles,
                        token: tokenJWT
                    })
                    return
                }
            }
            res.status(200).json({ message: 'Login ou senha incorretos' }) 
        })
        .catch( err => {
            res.status(500).json({
                message: 'Erro ao verificar login - ' + err.message
            })
        })
})

module.exports = apiRouter