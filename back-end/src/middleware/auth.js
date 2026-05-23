
/*
 Este middleware intercepta todas as rotas e verifica se um token
 de autenticação foi enviado junto com a requisição
*/
import jwt from 'jsonwebtoken'


/*
 Algumas rotas, como /user/login, poderão ser acessadas sem a
 necessidade de apresentação do token
*/
const bypassRoutes = [
 { url: '/users/login', method: 'POST' }
]


export default function(req, res, next) {


 /*
   Verificamos se a rota interceptada corresponde a alguma das
   exceções cadastradas acima. Sendo o caso, permite continuar
   sem verificar a autorização
 */
 for(let route of bypassRoutes) {
   if(route.url === req.url && route.method === req.method) {
     next()    // Continua sem autenticação
     return
   }
 }


 /* PROCESSO DE VERIFICAÇÃO DO TOKEN DE AUTORIZAÇÃO */
 let token
  // Primeiramente, procura pelo token de autorização em um cookie
 token = req.cookies[process.env.AUTH_COOKIE_NAME]


 if(! token) {
   // Se não tiver sido encontrado o token no cookie,
   // procura pelo token no cabeçalho de autorização
   const authHeader = req.headers['authorization']


   console.log({authHeader})


   // Se o cabeçalho 'authorization' não existir, retorna
   // HTTP 403: Forbidden
   if(! authHeader) {
     console.error('ERRO DE AUTORIZAÇÃO: falta de cabeçalho')
     return res.status(403).end()
   }


   /*
     O cabeçalho 'autorization' tem o formato "Bearer XXXXXXXXXXXXXXX",
     onde "XXXXXXXXXXXXXXX" é o token. Portanto, precisamos dividir esse
     cabeçalho (string) em duas partes, cortando onde está o caractere de
     espaço e aproveitando apenas a segunda parte, que é onde está o token
   */
   [, token] = authHeader.split(' ')
 }




 // Validação do token
 jwt.verify(token, process.env.TOKEN_SECRET, (error, user) => {


   // Token inválido ou expirado, retorna
   // HTTP 403: Forbidden
   if(error) {
     console.error('ERRO DE AUTORIZAÇÃO: token inválido ou expirado')
     return res.status(403).end()
   }


   /*
     Se chegamos até aqui, o token está OK e temos as informações
     do usuário autenticado no parâmetro "user". Vamos guardar isso
     dentro do "req" para usar depois
   */
   req.authUser = user


   // Token verificado e validado, podemos prosseguir
   next()
  
 })
}

