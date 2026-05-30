/*
 Este middleware intercepta todas as rotas e verifica se um token
 de autenticação foi enviado junto com a requisição.
*/
import jwt from 'jsonwebtoken'

/*
 Algumas rotas, como /users/login, podem ser acessadas sem a
 necessidade de apresentação do token.
*/
const bypassRoutes = [
  { url: '/users/login', method: 'POST' }
]

export default function(req, res, next) {
  if(req.method === 'OPTIONS') return next()

  /*
    Verificamos se a rota interceptada corresponde a alguma das
    exceções cadastradas acima. Sendo o caso, permite continuar
    sem verificar a autorização.
  */
  for(let route of bypassRoutes) {
    if(route.url === req.path && route.method === req.method) {
      next()
      return
    }
  }

  /* PROCESSO DE VERIFICAÇÃO DO TOKEN DE AUTORIZAÇÃO */
  let token = req.cookies?.[process.env.AUTH_COOKIE_NAME]

  if(!token) {
    const authHeader = req.headers.authorization

    if(!authHeader) {
      return res.status(401).end()
    }

    const [scheme, headerToken] = authHeader.split(' ')
    if(scheme !== 'Bearer' || !headerToken) {
      return res.status(401).end()
    }

    token = headerToken
  }

  // Validação do token
  jwt.verify(token, process.env.TOKEN_SECRET, (error, user) => {
    if(error) {
      return res.status(401).end()
    }

    /*
      Se chegamos até aqui, o token está OK e temos as informações
      do usuário autenticado no parâmetro "user". Vamos guardar isso
      dentro do "req" para usar depois.
    */
    req.authUser = user

    next()
  })
}
