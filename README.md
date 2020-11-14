# Socks 5 Daemon

Implementacion de un proxy socks 5 en C para la materia Protocolos de Comunicacion. Profesores Juan Codagnone y Marcelo Garberoglio. 

Hecho por

- [Brandy, Tobias](https://github.com/tobiasbrandy)
- [Pannunzio, Faustino](https://github.com/Fpannunzio)
- [Sagues, Ignacio](https://github.com/isagues)

## Objetivo

Desarrollar un servidor proxy socks 5 que soporte

- Autenticacion con user/pass.
- Comando connect con los 3 tipos de address.
- Resolucion de nombres de dominio via queries DoH.
- Sniffing de contraseñas en comunicacion POP3 y HTTP.
- Protocolo de administracion para realizar ajustes de configuracion en tiempo de ejecucion

Ademas del servidor, desarrollar un cliente que permita utilizar todo el potencial del protocolo implementado.

## Compilacion

Para la compilacion del servidor basta con correr `make all` o en su defecto `make`. Una vez corrido se generaran en el directorio principal los ejecutables asociados al servidor y al cliente para el protocolo de administracion. Los ejecutables son `socks5d` y `pipoClient` respectivamente.

## Testing

Para la ejecucion de los testeos de unidad implementados es necesario tener la libreria check instalada (`sudo apt install check` en Ubuntu/Debian) y ejecutar `make tests`. Este procedimiento se encarga de compilar los archivos de test y ejecutarlos, imprimiendo a salida el resultado de los mismos.

## Ejecucion

Para la ejecucion del servido basta con correrlo sin utilizar ningun parametro. De todas formas, el ejecutable cuenta con una lista de parametros para configurar opciones vinculadas a la direccion y puertos de binding, ajustes para el servidor DoH a utilizar, entre otros. Todos estos parametros puede ser encontrados en el archivo man `socks5d.8` o ejecuando el servidor con de la siguiente forma `./socks5d -h`.

## Informacion extra

En el archivo `informe.pdf` se puede encontrar un desarrollo de las decisiones de diseño, problemas encontrados, pruebas realizas y una descripcion un poco mas detallada del proyecto.
Ademas, en el archivo `pipoProtocol.txt` se puede encontrar una descripcion detalla del protocolo de administracion diseñado e implementado. 
Por ultimo, en el archivo `enunciado.txt` se encuentra la consiga del trabajo realizado.
