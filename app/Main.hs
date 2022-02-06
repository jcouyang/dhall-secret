{-# LANGUAGE NamedFieldPuns #-}
module Main where

import qualified Data.Text           as T
import qualified Data.Text.IO        as TIO
import           Dhall               (inputExpr)
import           Dhall.Core          (pretty)
import           Lib
import           Options.Applicative

data EncryptOpts = EncryptOpts
  { eo'file    :: Maybe String
  , eo'inplace :: Bool
  , eo'output  :: Maybe String
  }

data DecryptOpts = DecryptOpts
  { do'file    :: Maybe String
  , do'inplace :: Bool
  , do'output  :: Maybe String}

data Command = Encrypt EncryptOpts | Decrypt DecryptOpts

encryptOpt = EncryptOpts
  <$> optional (strOption
                (long "file"
                <> short 'f'
                <> metavar "FILE"
                <> help "read expression from file to encrypt"))
  <*> switch (long "in-place" <> short 'i' <> help "encrypt file in place")
  <*> optional (strOption
               (long "output"
               <> short 'o'
               <> metavar "FILE"
               <> help "write result to a file instead of stdout"))

decryptOpt = DecryptOpts
  <$> optional (strOption
                (long "file"
                <> short 'f'
                <> metavar "FILE"
                <> help "read expression from file to encrypt"))
  <*> switch (long "in-place" <> short 'i' <> help "decrypt file in place")
  <*> optional (strOption
               (long "output"
               <> short 'o'
               <> metavar "FILE"
               <> help "write result to a file instead of stdout"))

encryptCmdParser = hsubparser $ command "encrypt" (info encryptOpt (progDesc "encrypt dhall file")) <> metavar "encrypt"

decryptCmdParser = hsubparser $ command "decrypt" (info decryptOpt (progDesc "encrypt dhall file")) <> metavar "decrypt"

commands = Encrypt <$> encryptCmdParser <|> Decrypt <$>decryptCmdParser

main :: IO ()
main = exec =<< execParser opts
  where
    opts =
      info
        (commands <**> helper)
        ( fullDesc
            <> header "dhall-secret"
        )

exec :: Command -> IO ()
exec (Encrypt EncryptOpts {eo'file, eo'output, eo'inplace}) = ioDhallExpr eo'file eo'output eo'inplace encrypt
exec (Decrypt DecryptOpts {do'file, do'output, do'inplace}) = ioDhallExpr do'file do'output do'inplace decrypt

ioDhallExpr input output inplace op = do
  text <- maybe TIO.getContents TIO.readFile input
  expr <- inputExpr text
  encrypted <- pretty <$> op expr
  maybe (TIO.putStrLn encrypted) (`TIO.writeFile` encrypted) (output <|> (if  inplace then input else Nothing))
