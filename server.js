const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const mysql = require('mysql2');
const cors = require('cors');
const multer = require('multer');
const nodemailer = require('nodemailer');
const app = express();

// Configuración de multer para manejar la carga de archivos
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024, // Limita el tamaño del archivo a 5MB
  },
});



app.use(bodyParser.json());
app.use(cors({
  origin: 'http://localhost:4200',  // Cambia 'localhost:4200' por la URL de tu frontend
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true,
  allowedHeaders: 'Content-Type, Authorization'
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const dbConfig = {
  host: '127.0.0.1',
  user: 'root',
  password: 'duocswap',
  database: 'matchs', 
  port:3307
};

const pool = mysql.createPool(dbConfig);

// Inicia el servidor después de probar la conexión a la base de datos
pool.getConnection((err, connection) => {
  if (err) {
    console.error('Error al conectar a la base de datos:', err.stack);
    return;
  }

  console.log('Conectado a la base de datos ');
  connection.release(); 

  // Inicia el servidor solo después de una conexión exitosa
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
  });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send({ message: 'El nombre de usuario y la contraseña son requeridos' });
  }

  try {
    // Verificar si hay usuarios en la tabla Usuario
    pool.query('SELECT COUNT(*) AS userCount FROM Usuario', (err, result) => {
      if (err) {
        console.error('Error durante la consulta:', err);
        return res.status(500).send({ message: 'Error interno del servidor' });
      }

      const userCount = result[0].userCount;

      // Si no hay usuarios registrados, permitir el login con las credenciales de administrador
      if (userCount === 0) {
        if (username === 'root' && password === '123456') {
          const rootUser = { id: 0, username: 'root' }; 
          const token = generateToken(rootUser); 
          return res.status(200).send({ message: 'Login realizado exitosamente con usuario administrador', token });
        } else {
          return res.status(401).send({ message: 'Credenciales inválidas' });
        }
      } else {
        // Si hay usuarios registrados, proceder con la autenticación normal
        pool.query('SELECT * FROM Usuario WHERE NombreUsuario = ?', [username], (err, results) => {
          if (err) {
            console.error('Error durante la consulta:', err);
            return res.status(500).send({ message: 'Error interno del servidor' });
          }

          if (results.length === 0) {
            return res.status(401).send({ message: 'Credenciales inválidas' });
          }

          const user = results[0];
          const Contrasena = user.Contrasena;

          if (bcrypt.compareSync(password, Contrasena)) {
            const token = generateToken(user); // Genera un token (implementa esta función)
            return res.status(200).send({ message: 'Login realizado exitosamente', token });
          } else {
            return res.status(401).send({ message: 'Credenciales inválidas' });
          }
        });
      }
    });
  } catch (err) {
    console.error('Error durante el login:', err);
    res.status(500).send({ message: 'Error interno del servidor' });
  }
});


// Función para generar un token 
function generateToken(user) {
  // Implementa la lógica para generar un token, por ejemplo usando jsonwebtoken
  return 'token'; // Reemplaza esto con el token real
}

// Obtener todas las tablas de la base de datos
app.get('/tables/:table', (req, res) => {
  const tableName = req.params.table;
  const validTables = [
  'Estudiante',
  'Usuario',
  'Herramienta',
  'Matchs',
  'Chats'

];

  if (!validTables.includes(tableName)) {
    return res.status(400).send({ message: 'Nombre de tabla no válido' });
  }

  pool.query(`SELECT * FROM ??`, [tableName], (err, results) => {
    if (err) {
      console.error('Error durante la consulta:', err);
      return res.status(500).send({ message: 'Error interno del servidor' });
    }
    res.status(200).send(results);
  });
});


//---------------------------------LoginStudent---------------------------------------------------------------
// inicio de sesión de loginStudent
app.post('/loginStudent', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send({ message: 'El nombre de usuario y la contraseña son requeridos' });
  }

  try {
    // Consulta directamente la base de datos para verificar el usuario
    pool.query('SELECT * FROM Estudiante WHERE NombreUsuario = ?', [username], (err, results) => {
      if (err) {
        console.error('Error durante la consulta:', err);
        return res.status(500).send({ message: 'Error interno del servidor' });
      }

      // Si no hay resultados, el usuario no existe
      if (results.length === 0) {
        return res.status(401).send({ message: 'Credenciales inválidas' });
      }

      const student = results[0];
      const hashedPassword = student.Contrasena;

      // Verificar la contraseña usando bcrypt
      if (bcrypt.compareSync(password, hashedPassword)) {
        // Generar token usando los datos relevantes del estudiante
        const token = generateToken({ id: student.IdEstudiante, username: student.NombreUsuario });

        // Responder con el token y el id del estudiante
        return res.status(200).send({ 
          message: 'Login realizado exitosamente', 
          token: token, 
          idEstudiante: student.IdEstudiante 
        });
      } else {
        // Contraseña incorrecta
        return res.status(401).send({ message: 'Credenciales inválidas' });
      }
    });
  } catch (err) {
    console.error('Error durante el login del estudiante:', err);
    res.status(500).send({ message: 'Error interno del servidor' });
  }
});

// Función para generar un token (usando JSON Web Token, por ejemplo)
function generateToken(student) {
  // Aquí puedes usar la librería jsonwebtoken para generar un token real
  // return jwt.sign(student, 'secreto_del_servidor', { expiresIn: '1h' });
  return 'token'; // Token ficticio; reemplazar con un JWT real
}



//-------------------------Nuevo Material---------------------------------------------------
// Añadir un nuevo Herramienta
app.post('/addTool', upload.single('portada'), (req, res) => {
  console.log('Cuerpo de la solicitud:', req.body);
  console.log('Archivo recibido:', req.file);

  const { serie, tipo, marca, modelo, categoria, descripcion, cantidades } = req.body;
  const portada = req.file ? req.file.buffer : null;

  console.log('Campos extraídos:', { serie, tipo, marca, modelo, categoria, descripcion, cantidades });

  if (!serie || !tipo || !marca || !modelo || !categoria || !cantidades) {
    console.log('Campos faltantes:', { serie, tipo, marca, modelo, categoria, cantidades });
    return res.status(400).json({ message: 'Todos los campos son obligatorios' });
  }

  const ejemplares = parseInt(cantidades, 10);
  if (isNaN(ejemplares)) {
    return res.status(400).json({ message: 'El número de Stock debe ser un número válido' });
  }

  const query = 'INSERT INTO Herramienta (SERIE, Tipo, Marca, Modelo, Categoria, Descripcion, Cantidades, Portada) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
  const values = [serie, tipo, marca, modelo, categoria, descripcion || null, ejemplares, portada];

  pool.query(query, values, (err) => {
    if (err) {
      console.error('Error durante la inserción:', err);
      return res.status(500).json({ message: 'Error interno del servidor' });
    }

    res.status(201).json({ message: 'Herramienta registrado exitosamente' });
  });
});

// Rutas para manejar Herramientas

// Actualizar solo la cantidad de stock
app.put('/updateTool/quantity/:serie', (req, res) => {
  const { serie } = req.params;
  const { Cantidades } = req.body;

  console.log('Datos recibidos para actualizar cantidad:', req.body);

  if (Cantidades === undefined) {
    return res.status(400).json({ message: 'El campo Cantidades es obligatorio' });
  }

  const query = 'UPDATE Herramienta SET Cantidades = ? WHERE SERIE = ?';
  const values = [Cantidades, serie];

  pool.query(query, values, (err, result) => {
    if (err) {
      console.error('Error al actualizar la cantidad de Stock:', err);
      return res.status(500).json({ message: 'Error interno del servidor', error: err.message });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Herramienta no encontrado' });
    }

    res.status(200).json({ message: 'Cantidad de herramientas actualizada exitosamente' });
  });
});

// Actualizar un herramienta (detalles)
app.put('/updateTool/:serie', upload.single('portada'), (req, res) => {
  const { serie } = req.params;
  const { Tipo, Marca, Modelo, Categoria, Descripcion, Cantidades } = req.body;
  const portada = req.file ? req.file.buffer : null;

  console.log('Datos recibidos para actualizar herramienta:', req.body);
  console.log('Archivo recibido:', req.file);

  if (!Tipo || !Marca || !Modelo || !Categoria || Cantidades === undefined) {
    return res.status(400).json({ message: 'Todos los campos son obligatorios', camposFaltantes: { Tipo, Marca, Modelo, Categoria, Cantidades } });
  }

  let query = 'UPDATE Herramienta SET Tipo = ?, Marca = ?, Modelo = ?, Categoria = ?, Descripcion = ?, Cantidades = ?';
  let values = [Tipo, Marca, Modelo, Categoria, Descripcion, Cantidades];

  if (portada) {
    query += ', Portada = ?';
    values.push(portada);
  }

  query += ' WHERE SERIE = ?';
  values.push(serie);

  pool.query(query, values, (err, result) => {
    if (err) {
      console.error('Error al actualizar el herramienta:', err);
      return res.status(500).json({ message: 'Error interno del servidor', error: err.message });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Herramienta no encontrado' });
    }

    res.status(200).json({ message: 'Herramienta actualizado exitosamente' });
  });
});


// Ruta para eliminar una herramienta por SERIE
app.delete('/deleteTool/:serie', (req, res) => {
  const { serie } = req.params;
  
  // SQL para eliminar la herramienta
  const deleteToolQuery = 'DELETE FROM Herramienta WHERE SERIE = ?';
  
  pool.query(deleteToolQuery, [serie], (err, result) => {
    if (err) {
      console.error('Error al eliminar la herramienta:', err);
      return res.status(500).send({ message: 'Error interno del servidor' });
    }
    
    if (result.affectedRows === 0) {
      // Si no se encontró el registro
      return res.status(404).send({ message: 'Herramienta no encontrada' });
    }
    
    res.status(200).send({ message: 'Herramienta eliminada con éxito' });
  });
});




// Nueva ruta para buscar herramientas
app.get('/searchTools', (req, res) => {
  const { busqueda, marca, categoria, tipo } = req.query;
  let query = 'SELECT SERIE, Tipo, Marca, Modelo, Categoria, Descripcion, Cantidades, Portada FROM Herramienta WHERE 1=1';
  const params = [];

  if (busqueda) {
    query += ' AND (Tipo LIKE ? OR Marca LIKE ? OR SERIE LIKE ?)';
    params.push(`%${busqueda}%`, `%${busqueda}%`, `%${busqueda}%`);
  }
  if (marca) {
    query += ' AND Marca = ?';
    params.push(marca);
  }
  if (categoria) {
    query += ' AND Categoria = ?';
    params.push(categoria);
  }
  if (tipo) {
    query += ' AND Tipo = ?';
    params.push(tipo);
  }

  pool.query(query, params, (err, results) => {
    if (err) {
      console.error('Error durante la búsqueda de herramientas:', err);
      return res.status(500).send({ message: 'Error interno del servidor' });
    }
    res.status(200).send(results);
  });
});


// Nueva ruta para match de herramientas
app.post('/loanTool', (req, res) => {
  const { idEstudiante, serie, fechaMatch, fechaEstimacion, idUsuario } = req.body;

  // Verificar si el número del usuario es proporcionado
  if (!idEstudiante) {
      return res.status(400).send({ message: 'Ingresa el número de usuario correspondiente' });
  }

  // Verificar si las fechas son válidas
  if (!fechaMatch || !fechaEstimacion) {
      return res.status(400).send({ message: 'Las fechas de match y estimación son requeridas' });
  }

  const sql = 'INSERT INTO Match (IdEstudiante, SERIE, FechaMatch, FechaEstimacion, IdUsuario) VALUES (?, ?, ?, ?, ?)';
  const values = [idEstudiante, serie, fechaMatch, fechaEstimacion, idUsuario];

  pool.query(sql, values, (err, results) => {
      if (err) {
          console.error('Error durante la inserción del match:', err);
          return res.status(500).send({ message: 'Error interno del servidor' });
      }

      // Actualizar la cantidad de Stock después de registrar el match
      const updateQuery = 'UPDATE Herramienta SET Cantidades = Cantidades - 1 WHERE SERIE = ?';
      pool.query(updateQuery, [serie], (updateErr, updateResult) => {
          if (updateErr) {
              console.error('Error al actualizar la cantidad de Stock:', updateErr);
              return res.status(500).send({ message: 'Error interno del servidor' });
          }

          res.status(201).send({ message: 'match registrado y cantidad de herramientas actualizada exitosamente' });
      });
  });
});

    // Configuración de nodemailer
    const userDuocuc = "";
    const passAppDuocuc = "";
    
    const transporter = nodemailer.createTransport({
      service: "duocuc",
      auth: {
        user: userDuocuc,
        pass: passAppDuocuc,
      },
      tls: {
        rejectUnauthorized: false,}

    });

    const crypto = require('crypto'); // Importar crypto para generar tokens

//-------------------------USUARIOS---------------------------------------------
// Añadir un nuevo Usuario
app.post('/usuarios', (req, res) => {
  const { NombreCompleto, Correo, Telefono, IdAdmin, NombreUsuario, Contrasena } = req.body;
  
  if (!NombreCompleto || !Correo || !Telefono || !NombreUsuario || !Contrasena) {
    return res.status(400).send({ message: 'Todos los campos son obligatorios' });
  }
  const salt = bcrypt.genSaltSync(10);
  const hash = bcrypt.hashSync(Contrasena, salt);
  
  const query = 'INSERT INTO Usuario (NombreCompleto, Correo, Telefono, IdAdmin, NombreUsuario, Contrasena) VALUES (?, ?, ?, ?, ?, ?)';
  const values = [NombreCompleto, Correo, Telefono, IdAdmin, NombreUsuario, hash];
  
  pool.query(query, values, (err) => {
    if (err) {
      console.error('Error durante la inserción:', err);
      return res.status(500).send({ message: 'Error interno del servidor' });
    }
  
    res.status(201).send({ message: 'Usuario registrado exitosamente' });
  });
  });
  
  // Actualizar un Usuario
  app.put('/usuarios/:id', (req, res) => {
  const { id } = req.params;
  const { NombreCompleto, Correo, Telefono, IdAdmin, NombreUsuario, Contrasena } = req.body;
  
  if (!NombreCompleto || !Correo || !Telefono || !IdAdmin || !NombreUsuario || !Contrasena) {
    return res.status(400).json({ message: 'Todos los campos son obligatorios' });
  }
  
  const salt = bcrypt.genSaltSync(10);
  const hash = bcrypt.hashSync(Contrasena, salt);
  
  const query = 'UPDATE Usuario SET NombreCompleto = ?, Correo = ?, Telefono = ?, IdAdmin = ?, NombreUsuario = ?, Contrasena = ? WHERE IdUsuario = ?';
  const values = [NombreCompleto, Correo, Telefono, IdAdmin, NombreUsuario, hash, id];
  
  pool.query(query, values, (err, result) => {
    if (err) {
      console.error('Error al actualizar el usuario:', err);
      return res.status(500).json({ message: 'Error interno del servidor' });
    }
  
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }
  
    res.status(200).json({ message: 'Usuario actualizado exitosamente' });
  });
  });
  
  // Eliminar un usuario
  app.delete('/usuarios/:id', (req, res) => {
  const { id } = req.params;
  
  pool.query('DELETE FROM Usuario WHERE IdUsuario = ?', [id], (err) => {
    if (err) {
      console.error('Error durante la eliminación:', err);
      return res.status(500).send({ message: 'Error interno del servidor' });
    }
  
    res.status(200).send({ message: 'Usuario eliminado exitosamente' });
  });
  });
  
  // Buscar usuarios
  app.get('/usuarios', (req, res) => {
  const { busqueda, NombreUsuario, Correo, NombreCompleto } = req.query;
  let query = 'SELECT * FROM Usuario WHERE 1=1';
  const params = [];
  
  if (busqueda) {
    query += ' AND (NombreCompleto LIKE ? OR NombreUsuario LIKE ? OR Correo LIKE ?)';
    params.push(`%${busqueda}%`, `%${busqueda}%`, `%${busqueda}%`);
  }
  if (NombreUsuario) {
    query += ' AND NombreUsuario = ?';
    params.push(NombreUsuario);
  }
  if (Correo) {
    query += ' AND Correo = ?';
    params.push(Correo);
  }
  if (NombreCompleto) {
    query += ' AND NombreCompleto = ?';
    params.push(NombreCompleto);
  }
  
  pool.query(query, params, (err, results) => {
    if (err) {
      console.error('Error durante la búsqueda de usuarios:', err);
      return res.status(500).send({ message: 'Error interno del servidor' });
    }
    res.status(200).send(results);
  });
  });
    

//-------------------ESTUDIANTE------------------------------------------------

// Añadir un nuevo estudiante
app.post('/estudiantes', (req, res) => {
  const { NombreCompleto, Correo, Telefono, IdStudent, NombreUsuario, Contrasena } = req.body;
  
  if (!NombreCompleto || !Correo || !Telefono || !NombreUsuario || !Contrasena) {
    return res.status(400).send({ message: 'Todos los campos son obligatorios' });
  }
  const salt = bcrypt.genSaltSync(10);
  const hash = bcrypt.hashSync(Contrasena, salt);
  
  const query = 'INSERT INTO Estudiante (NombreCompleto, Correo, Telefono, IdStudent, NombreUsuario, Contrasena) VALUES (?, ?, ?, ?, ?, ?)';
  const values = [NombreCompleto, Correo, Telefono, IdStudent, NombreUsuario, hash];
  
  pool.query(query, values, (err) => {
    if (err) {
      console.error('Error durante la inserción:', err);
      return res.status(500).send({ message: 'Error interno del servidor' });
    }
  
    res.status(201).send({ message: 'Estudiante registrado exitosamente' });
  });
  });
  
  // Actualizar un Estudiante
  app.put('/estudiantes/:id', (req, res) => {
  const { id } = req.params;
  const { NombreCompleto, Correo, Telefono, IdStudent, NombreUsuario, Contrasena } = req.body;
  
  if (!NombreCompleto || !Correo || !Telefono || !IdStudent || !NombreUsuario || !Contrasena) {
    return res.status(400).json({ message: 'Todos los campos son obligatorios' });
  }
  
  const salt = bcrypt.genSaltSync(10);
  const hash = bcrypt.hashSync(Contrasena, salt);
  
  const query = 'UPDATE Estudiante SET NombreCompleto = ?, Correo = ?, Telefono = ?, IdStudent = ?, NombreUsuario = ?, Contrasena = ? WHERE IdEstudiante = ?';
  const values = [NombreCompleto, Correo, Telefono, IdStudent, NombreUsuario, hash, id];
  
  pool.query(query, values, (err, result) => {
    if (err) {
      console.error('Error al actualizar el estudiante:', err);
      return res.status(500).json({ message: 'Error interno del servidor' });
    }
  
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: 'Estudiante no encontrado' });
    }
  
    res.status(200).json({ message: 'Estudiante actualizado exitosamente' });
  });
  });
  
  // Eliminar un Estudiante
  app.delete('/estudiantes/:id', (req, res) => {
  const { id } = req.params;
  
  pool.query('DELETE FROM Estudiante WHERE IdEstudiante = ?', [id], (err) => {
    if (err) {
      console.error('Error durante la eliminación:', err);
      return res.status(500).send({ message: 'Error interno del servidor' });
    }
  
    res.status(200).send({ message: 'Estudiante eliminado exitosamente' });
  });
  });
  
  // Buscar estudiantes
  app.get('/estudiantes', (req, res) => {
  const { busqueda, NombreUsuario, Correo, NombreCompleto } = req.query;
  let query = 'SELECT * FROM Estudiante WHERE 1=1';
  const params = [];
  
  if (busqueda) {
    query += ' AND (NombreCompleto LIKE ? OR NombreUsuario LIKE ? OR Correo LIKE ?)';
    params.push(`%${busqueda}%`, `%${busqueda}%`, `%${busqueda}%`);
  }
  if (NombreUsuario) {
    query += ' AND NombreUsuario = ?';
    params.push(NombreUsuario);
  }
  if (Correo) {
    query += ' AND Correo = ?';
    params.push(Correo);
  }
  if (NombreCompleto) {
    query += ' AND NombreCompleto = ?';
    params.push(NombreCompleto);
  }
  
  pool.query(query, params, (err, results) => {
    if (err) {
      console.error('Error durante la búsqueda de estudiantes:', err);
      return res.status(500).send({ message: 'Error interno del servidor' });
    }
    res.status(200).send(results);
  });
  });
  
  // Manejador de errores global
  app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Algo salió mal!');
  });


// Iniciar un chat
router.post('/crear-chat', async (req, res) => {
  const { idEstudiante, idMatch } = req.body;
  try {
      await db.query('CALL CrearChat(?, ?)', [idEstudiante, idMatch]);
      res.status(200).json({ message: 'Chat iniciado correctamente.' });
  } catch (error) {
      console.error('Error al iniciar el chat:', error);
      res.status(500).json({ error: 'Error al iniciar el chat.' });
  }
});

// Enviar un mensaje
router.post('/enviar-mensaje', async (req, res) => {
  const { idEstudiante, idMatch, mensaje } = req.body;
  try {
      await db.query('CALL EnviarMensaje(?, ?, ?)', [idEstudiante, idMatch, mensaje]);
      res.status(200).json({ message: 'Mensaje enviado correctamente.' });
  } catch (error) {
      console.error('Error al enviar el mensaje:', error);
      res.status(500).json({ error: 'Error al enviar el mensaje.' });
  }
});

// Obtener mensajes por Match
router.get('/mensajes/:idMatch', async (req, res) => {
  const { idMatch } = req.params;
  try {
      const [rows] = await db.query('SELECT * FROM Chats WHERE IdMatch = ?', [idMatch]);
      res.status(200).json(rows);
  } catch (error) {
      console.error('Error al obtener los mensajes:', error);
      res.status(500).json({ error: 'Error al obtener los mensajes.' });
  }
});

module.exports = router;


//---------------------Matchs----------------------------------------------------------------------

//Obtener todos los matchs V2
app.get('/loan', (req, res) => {
  const query = `
  SELECT m.IdMatch, m.SERIE, m.IdEstudiante, m.FechaMatch, m.FechaEstimacion, l.Tipo
  FROM Matchs m
  JOIN Herramienta l ON m.SERIE = l.SERIE
  WHERE m.Estado = 'Pendiente'
`;

  pool.query(query, (err, results) => {
    if (err) {
      console.error('Error al obtener matchs:', err);
      return res.status(500).json({ error: 'Error interno del servidor' });
    }
    res.json(results);
  });
});

 //Obtener todos los matchs
app.get('/loans', (req, res) => {
  const query = `
  SELECT m.IdMatch as id, m.SERIE, m.IdEstudiante, m.FechaMatch, m.FechaEstimacion, l.Tipo
  FROM Matchs m
  JOIN Herramienta l ON m.SERIE = l.SERIE
  WHERE m.Estado = 'Pendiente'
`;

  pool.query(query, (err, results) => {
    if (err) {
      console.error('Error al obtener matchs:', err);
      return res.status(500).json({ error: 'Error interno del servidor' });
    }
    res.json(results);
  });
});

// Devolver un herramienta
app.delete('/returnTool/:id', (req, res) => {
  const { id } = req.params;
  console.log('ID del match a devolver:', id);

  pool.query('SELECT SERIE FROM Matchs WHERE IdMatch = ? ', [id,], (err, result) => {
    if (err) {
      console.error('Error al obtener el SERIE del match:', err);
      return res.status(500).json({ error: 'Error interno del servidor' });
    }

    console.log('Resultado de la consulta:', result); // Para verificar qué se está devolviendo

    if (result.length === 0) {
      return res.status(404).json({ error: 'match no encontrado' });
    }

    const serie = result[0].SERIE;

    pool.query('Update Matchs SET Estado = ? WHERE IdMatch = ?', ['Devuelto',id], (err) => {
      if (err) {
        console.error('Error al devolver el herramienta:', err);
        return res.status(500).json({ error: 'Error interno del servidor' });
      }

      pool.query('SELECT Cantidades FROM Herramienta WHERE SERIE = ?', [serie], (err, toolResult) => {
        if (err) {
          console.error('Error al obtener la cantidad de Stock del herramienta:', err);
          return res.status(500).json({ error: 'Error interno del servidor' });
        }
        if (toolResult.length === 0) {
          return res.status(404).json({ error: 'Herramienta no encontrado' });
        }

        const currentQuantity = toolResult[0].Cantidades;

        const newQuantity = currentQuantity + 1; // Aquí solo sumas 1 al eliminar el match
        pool.query('UPDATE Herramienta SET Cantidades = ? WHERE SERIE = ?', [newQuantity, serie], (err) => {
          if (err) {
            console.error('Error al actualizar la cantidad de Stock:', err);
            return res.status(500).json({ error: 'Error interno del servidor' });
          }

          res.json({ message: 'match eliminado y cantidad de herramientas actualizada exitosamente' });
        });
      });
    });
  });
});


// End point para el reporte personalizado
app.get('/Reporte', (req, res) => {
  const { fechaInicio, fechaFin } = req.query;

  let query = `
    SELECT 
      m.IdMatch,
      m.IdEstudiante,
      l.NombreCompleto AS NombreMatchs,
      l.Correo AS CorreoMatchs,
      m.SERIE,
      lb.Tipo AS TipoHerramienta,
      lb.Marca AS MarcaHerramienta,
      m.FechaMatch,
      m.FechaEstimacion,
      m.IdEstudiante,
      m.Estado
    FROM Match m
    JOIN Matchs l ON m.IdEstudiante = l.IdEstudiante
    JOIN Herramienta lb ON m.SERIE = lb.SERIE
  `;

  let queryParams = [];

  if (fechaInicio && fechaFin) {
    query += ` WHERE m.FechaPrestamo BETWEEN ? AND ?`;
    queryParams.push(fechaInicio, fechaFin);
  }

  pool.query(query, queryParams, (err, results) => {
    if (err) {
      console.error('Error ejecutando la consulta:', err);
      res.status(500).send('Error al obtener los matchs.');
    } else {
      console.log('Resultados de la consulta:', results); // Aquí inspeccionas los resultados
      res.json(results);
    }
  });
});



// Obtener un matchs por su número de usuario
app.get('/matchs/:idEstudiante', (req, res) => {
  const { idEstudiante } = req.params;

  pool.query('SELECT * FROM Matchs WHERE IdEstudiante = ?', [idEstudiante], (err, results) => {
      if (err) {
          console.error('Error al obtener el matchs:', err);
          return res.status(500).send({ message: 'Error interno del servidor' });
      }
      if (results.length === 0) {
          return res.status(404).send({ message: 'matchs no encontrado' });
      }
      res.status(200).send(results[0]);
  });
});
