import React from 'react'
import Typography from '@mui/material/Typography'
import Table from '@mui/material/Table'
import TableBody from '@mui/material/TableBody'
import TableCell from '@mui/material/TableCell'
import TableContainer from '@mui/material/TableContainer'
import TableHead from '@mui/material/TableHead'
import TableRow from '@mui/material/TableRow'
import Paper from '@mui/material/Paper'


export default function Homepage() {


 const [ls, setLs] = React.useState([])


 React.useEffect(() => {
   const _ls = []
   for (let i = 0; i < window.localStorage.length; i++) {
     const key = window.localStorage.key(i)
     const value = window.localStorage.getItem(key)
     _ls.push({ [key]: value })
   }
   console.log(_ls)
   setLs(_ls)
 }, [])


 return (
   <>
     <Typography variant="h1" gutterBottom>
       Projeto VULCOM
     </Typography>


     <Typography>
       Sistema para análise e estudo de vulnerabilidades comuns
     </Typography>


     <Typography variant="h5">
       Exposição de valores do <em>local storage</em>
       <TableContainer component={Paper}>
         <Table>
           <TableHead>
             <TableRow>
               <TableCell>Chave</TableCell>
               <TableCell>Valor</TableCell>
             </TableRow>
           </TableHead>
           <TableBody>
             {ls.map((kv, index) => (
               <TableRow key={index}>
                 <TableCell>{Object.keys(kv)[0]}</TableCell>
                 <TableCell>{kv[Object.keys(kv)[0]]}</TableCell>
               </TableRow>
             ))}
           </TableBody>
         </Table>
       </TableContainer>
     </Typography>


     <Typography variant="h5">
       Exposição de <em>cookies</em>
       <Typography variant="caption" style={{ fontFamily: 'monospace ' }}>
         <p>{document.cookie}</p>
       </Typography>
     </Typography>
   </>
 )
}
