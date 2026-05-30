import prisma from '../database/client.js'
import jwt from 'jsonwebtoken'
import argon2 from 'argon2'

const ARGON2_CONFIG = {
  type: argon2.argon2id,  // variante recomendada do algoritmo
  memoryCost: 65536,      // 64 MB de memória máxima utilizada
  timeCost: 3,            // número de iterações
  parallelism: 4          // número de threads simultâneas
}

const controller = {}     // Objeto vazio

function pickFields(source, fields) {
  const result = {}
  for(const field of fields) {
    if(source?.[field] !== undefined) result[field] = source[field]
  }
  return result
}

function getCookieOptions(req, extra = {}) {
  const isHttps = req.secure || req.headers['x-forwarded-proto'] === 'https'

  return {
    httpOnly: true,
    secure: isHttps,
    sameSite: 'lax',
    path: '/',
    ...extra
  }
}

function getUserPayload(user) {
  return {
    id: user.id,
    fullname: user.fullname,
    username: user.username,
    email: user.email,
    is_admin: user.is_admin
  }
}

controller.create = async function (req, res) {
  try {

    // Somente usuários administradores podem acessar este recurso
    // HTTP 403: Forbidden
    if (!req?.authUser?.is_admin) return res.status(403).end()

    const data = pickFields(req.body, [
      'fullname',
      'username',
      'email',
      'password',
      'is_admin'
    ])

    // Caso exista o campo "password" em req.body, é
    // necessário gerar o hash da senha antes de
    // armazená-la no BD, usando o algoritmo argon2
    if (data.password) {
      data.password = await argon2.hash(data.password, ARGON2_CONFIG)
    }

    await prisma.user.create({ data })

    // HTTP 201: Created
    res.status(201).end()
  }

  catch (error) {
    console.error(error)

    // HTTP 500: Internal Server Error
    res.status(500).end()
  }
}

controller.retrieveAll = async function (req, res) {
  try {
    // Somente usuários administradores podem acessar este recurso
    // HTTP 403: Forbidden
    if (!req?.authUser?.is_admin) return res.status(403).end()

    const result = await prisma.user.findMany({
      omit: { password: true }
    })
    // HTTP 200: OK (implícito)
    res.send(result)
  }
  catch (error) {
    console.error(error)

    // HTTP 500: Internal Server Error
    res.status(500).end()
  }
}

controller.retrieveOne = async function (req, res) {
  try {
    // Somente usuários administradores ou o próprio usuário
    // autenticado podem acessar este recurso
    // HTTP 403: Forbidden
    if (!(req?.authUser?.is_admin ||
      Number(req?.authUser?.id) === Number(req.params.id)))
      return res.status(403).end()

    const result = await prisma.user.findUnique({
      omit: { password: true },
      where: { id: Number(req.params.id) }
    })

    // Encontrou ~> retorna HTTP 200: OK (implícito)
    if (result) res.send(result)
    // Não encontrou ~> retorna HTTP 404: Not Found
    else res.status(404).end()
  }
  catch (error) {
    console.error(error)

    // HTTP 500: Internal Server Error
    res.status(500).end()
  }
}

controller.update = async function (req, res) {
  try {

    // Somente usuários administradores ou o próprio usuário
    // autenticado podem acessar este recurso
    // HTTP 403: Forbidden
    if (!(req?.authUser?.is_admin ||
      Number(req?.authUser?.id) === Number(req.params.id)))
      return res.status(403).end()

    const data = pickFields(req.body, [
      'fullname',
      'username',
      'email',
      'password'
    ])

    if (req?.authUser?.is_admin && req.body?.is_admin !== undefined) {
      data.is_admin = req.body.is_admin
    }

    // Caso exista o campo "password" em req.body, é
    // necessário gerar o hash da senha antes de
    // armazená-la no BD, usando o algoritmo argon2
    if (data.password) {
      data.password = await argon2.hash(data.password, ARGON2_CONFIG)
    }

    const result = await prisma.user.update({
      where: { id: Number(req.params.id) },
      data
    })

    // Encontrou e atualizou ~> HTTP 204: No Content
    if (result) res.status(204).end()
    // Não encontrou (e não atualizou) ~> HTTP 404: Not Found
    else res.status(404).end()
  }

  catch (error) {
    if (error?.code === 'P2025') {
      res.status(404).end()
    }
    else {
      console.error(error)

      // HTTP 500: Internal Server Error
      res.status(500).end()
    }
  }
}

controller.delete = async function (req, res) {
  try {

    // Somente usuários administradores podem acessar este recurso
    // HTTP 403: Forbidden
    if (!req?.authUser?.is_admin) return res.status(403).end()

    await prisma.user.delete({
      where: { id: Number(req.params.id) }
    })

    // Encontrou e excluiu ~> HTTP 204: No Content
    res.status(204).end()
  }
  catch (error) {
    if (error?.code === 'P2025') {
      // Não encontrou e não excluiu ~> HTTP 404: Not Found
      res.status(404).end()
    }
    else {
      // Outros tipos de erro
      console.error(error)

      // HTTP 500: Internal Server Error
      res.status(500).end()
    }
  }
}

controller.login = async function (req, res) {
  try {

    // Busca o usuário no BD usando o valor dos campos
    // "username" OU "email"
    const user = await prisma.user.findFirst({
      where: {
        OR: [
          { username: req.body?.username },
          { email: req.body?.email }
        ]
      }
    })

    // Se o usuário não for encontrado, retorna
    // HTTP 401: Unauthorized
    if (!user) return res.status(401).end()

    let passwordIsValid = false

    try {
      passwordIsValid = await argon2.verify(user.password, req.body?.password ?? '')
    }
    catch {
      passwordIsValid = false
    }

    // Se a senha estiver errada, retorna
    // HTTP 401: Unauthorized
    if (!passwordIsValid) return res.status(401).end()

    const authUser = getUserPayload(user)

    // Usuário e senha OK, passamos ao procedimento de gerar o token
    const token = jwt.sign(
      authUser,                    // Dados do usuário
      process.env.TOKEN_SECRET,    // Senha para criptografar o token
      { expiresIn: '24h' }         // Prazo de validade do token
    )

    // Formamos o cookie para enviar ao front-end
    res.cookie(process.env.AUTH_COOKIE_NAME, token, getCookieOptions(req, {
      maxAge: 24 * 60 * 60 * 1000  // 24h
    }))

    // Retorna o usuário autenticado com HTTP 200: OK (implícito)
    res.send({ user: authUser })

  }
  catch (error) {
    console.error(error)

    // HTTP 500: Internal Server Error
    res.status(500).end()
  }
}

controller.me = function (req, res) {
  // Retorna as informações do usuário autenticado
  // HTTP 200: OK (implícito)
  res.send(req?.authUser)
}

controller.logout = function (req, res) {
  // Apaga no front-end o cookie que armazena o token de autorização
  res.clearCookie(process.env.AUTH_COOKIE_NAME, getCookieOptions(req))
  // HTTP 204: No Content
  res.status(204).end()
}

export default controller
