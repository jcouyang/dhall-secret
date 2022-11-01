{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE QuasiQuotes    #-}
module Main where

import qualified Data.Text           as T
import qualified Data.Text.IO        as TIO
import           Data.Void           (Void)
import           Dhall               (inputExpr)
import           Dhall.Core          (pretty)
import           Dhall.Secret
import           Dhall.Src
import           Dhall.TH
import           Options.Applicative
data EncryptOpts = EncryptOpts
  { eo'file    :: Maybe String
  , eo'inplace :: Bool
  , eo'output  :: Maybe String
  }

data DecryptOpts = DecryptOpts
  { do'file    :: Maybe String
  , do'inplace :: Bool
  , do'output  :: Maybe String
  , do'notypes :: Bool
  }

data GenTypesOpts = GenTypesOpts { gt'output :: Maybe String }

data Command = Encrypt EncryptOpts | Decrypt DecryptOpts | GenTypes GenTypesOpts

versionOpt = infoOption (T.unpack $ pretty version ) (long "version" <> short 'v' <> help "print version")

genTypesOpt = GenTypesOpts  <$> optional (strOption
                (long "output"
                <> short 'o'
                <> metavar "FILE"
                <> help "Output types into FILE"))

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

encryptCmdParser = hsubparser $ command "encrypt" (info encryptOpt (progDesc "Encrypt a Dhall expression")) <> metavar "encrypt"

decryptCmdParser = hsubparser $ command "decrypt" (info decryptOpt (progDesc "Decrypt a Dhall expression")) <> metavar "decrypt"

genTypesCmdParser = hsubparser $ command "gen-types" (info genTypesOpt (progDesc "generate types")) <> metavar "gen-types"

commands = Encrypt <$> encryptCmdParser
  <|> Decrypt <$>decryptCmdParser
  <|> GenTypes <$> genTypesCmdParser

main :: IO ()
main = exec =<< execParser opts
  where
    opts = info (commands <**> helper <**> versionOpt) fullDesc

exec :: Command -> IO ()
exec (Encrypt EncryptOpts {eo'file, eo'output, eo'inplace}) = ioDhallExpr eo'file eo'output eo'inplace encrypt
exec (Decrypt DecryptOpts {do'file, do'output, do'inplace, do'notypes}) = ioDhallExpr do'file do'output do'inplace (decrypt (DecryptPreference do'notypes))
exec (GenTypes GenTypesOpts {gt'output}) = do
  let a = pretty secretType
  maybe (TIO.putStrLn a) (`TIO.writeFile` a) gt'output

ioDhallExpr input output inplace op = do
  text <- maybe TIO.getContents TIO.readFile input
  expr <- inputExpr text
  procssed <- pretty . defineVar <$> op expr
  maybe (TIO.putStrLn procssed) (`TIO.writeFile` procssed) (output <|> (if  inplace then input else Nothing))
