{-# LANGUAGE NamedFieldPuns    #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes       #-}
module Main where

import qualified Data.Text.IO        as TIO
import           Data.Void           (Void)
import           Dhall.Core          (Expr, pretty)
import           Dhall.Secret
import           Dhall.Secret.IO     (parseExpr, prettyExpr, version)
import           Dhall.Secret.Type   (secretTypes)
import           Dhall.Src           (Src)
import           Options.Applicative
import Control.Monad
import qualified Data.Text               as T

data EncryptOpts = EncryptOpts
  { eo'file    :: Maybe String
  , eo'inplace :: Bool
  , eo'output  :: Maybe String
  }

data RotateOpts = RotateOpts
  { ro'file    :: Maybe String
  , ro'inplace :: Bool
  , ro'output  :: Maybe String
  , ro'agerp ::  [T.Text]
  }

data DecryptOpts = DecryptOpts
  { do'file    :: Maybe String
  , do'inplace :: Bool
  , do'output  :: Maybe String
  , do'notypes :: Bool
  }

data GenTypesOpts = GenTypesOpts { gt'output :: Maybe String }

data Command = Encrypt EncryptOpts | Decrypt DecryptOpts | GenTypes GenTypesOpts | Rotate RotateOpts

versionOpt :: Parser (a -> a)
versionOpt = infoOption version (long "version" <> short 'v' <> help "print version")

genTypesOpt :: Parser GenTypesOpts
genTypesOpt = GenTypesOpts  <$> optional (strOption
                (long "output"
                <> short 'o'
                <> metavar "FILE"
                <> help "Output types into FILE"))

encryptOpt :: Parser EncryptOpts
encryptOpt = EncryptOpts
  <$> optional (strOption
                (long "file"
                <> short 'f'
                <> metavar "FILE"
                <> help "Read expression from file to encrypt"))
  <*> switch (long "in-place" <> short 'i' <> help "encrypt file in place")
  <*> optional (strOption
               (long "output"
               <> short 'o'
               <> metavar "FILE"
               <> help "Write result to a file instead of stdout"))


rotateOpt :: Parser RotateOpts
rotateOpt = RotateOpts
  <$>  optional (strOption
                (long "file"
                <> short 'f'
                <> metavar "FILE"
                <> help "Read expression from file to encrypt"))
  <*> switch (long "in-place" <> short 'i' <> help "encrypt file in place")
  <*> optional (strOption
               (long "output"
               <> short 'o'
               <> metavar "FILE"
               <> help "Write result to a file instead of stdout"))

  <*> many (strOption (long "age-recipients" <> help "rotate with new age recipients"))

decryptOpt :: Parser DecryptOpts
decryptOpt = DecryptOpts
  <$> optional (strOption
                (long "file"
                <> short 'f'
                <> metavar "FILE"
                <> help "Read expression from file to encrypt"))
  <*> switch (long "in-place" <> short 'i' <> help "decrypt file in place")
  <*> optional (strOption
               (long "output"
               <> short 'o'
               <> metavar "FILE"
               <> help "Write result to a file instead of stdout"))
  <*> switch (long "plain-text" <> short 'p' <> help "decrypt into plain text without types")

encryptCmdParser :: Parser EncryptOpts
encryptCmdParser = hsubparser $ command "encrypt" (info encryptOpt (progDesc "Encrypt a Dhall expression")) <> metavar "encrypt"

rotateCmdParser :: Parser RotateOpts
rotateCmdParser = hsubparser $ command "rotate" (info rotateOpt (progDesc "Rotate secrets")) <> metavar "rotate"

decryptCmdParser :: Parser DecryptOpts
decryptCmdParser = hsubparser $ command "decrypt" (info decryptOpt (progDesc "Decrypt a Dhall expression")) <> metavar "decrypt"

genTypesCmdParser :: Parser GenTypesOpts
genTypesCmdParser = hsubparser $ command "gen-types" (info genTypesOpt (progDesc "generate types")) <> metavar "gen-types"


commands :: Parser Command
commands = Encrypt <$> encryptCmdParser
  <|> Rotate <$> rotateCmdParser
  <|> Decrypt <$>decryptCmdParser
  <|> GenTypes <$> genTypesCmdParser

main :: IO ()
main = exec =<< execParser opts
  where
    opts = info (commands <**> helper <**> versionOpt) fullDesc

exec :: Command -> IO ()
exec (Encrypt EncryptOpts {eo'file, eo'output, eo'inplace}) = ioDhallExpr eo'file eo'output eo'inplace encrypt
exec (Rotate RotateOpts {ro'file, ro'output, ro'inplace, ro'agerp}) = ioDhallExpr ro'file ro'output ro'inplace (decrypt (DecryptPreference False) >=> encrypt' ro'agerp)
exec (Decrypt DecryptOpts {do'file, do'output, do'inplace, do'notypes}) = ioDhallExpr do'file do'output do'inplace (decrypt (DecryptPreference do'notypes))
exec (GenTypes GenTypesOpts {gt'output}) = do
  let a = pretty secretTypes
  maybe (TIO.putStrLn a) (`TIO.writeFile` a) gt'output

ioDhallExpr :: Maybe FilePath -> Maybe FilePath -> Bool -> (Expr Src Void -> IO (Expr Src Void)) -> IO ()
ioDhallExpr input output inplace op = do
  text <- maybe TIO.getContents TIO.readFile input
  expr <- parseExpr text
  procssed <- op expr >>= prettyExpr
  maybe (TIO.putStrLn procssed) (`TIO.writeFile` procssed) (output <|> (if  inplace then input else Nothing))
