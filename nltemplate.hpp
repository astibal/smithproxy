/*
The MIT License (MIT)

Copyright (c) 2013 Tomas Andrle

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/

/*  Modified to fit purpose of smithproxy software needs.  */

#ifndef __Template_H__
#define __Template_H__


#include <string>
#include <sstream>
#include <vector>
#include <iostream>
#include <memory>


namespace ext {

namespace nltemplate {

namespace Private {
    

struct Token {
    int type;
    std::string value;
};


class Tokenizer {
public:
    Tokenizer( const std::string & text );
    Token next();
    
private:
    const char *text_ptr;
    long len;
    long pos;
    Token peek;
    bool peeking;
};


class Dictionary {
public:
    const std::string find( const std::string & name ) const;
    void set( const std::string & name, const std::string & value );

protected:
    std::vector<std::pair<std::string, std::string> > properties;
};


class Fragment {
public:
    virtual void render( std::ostream & output, const Dictionary & dictionary ) const = 0;
    virtual ~Fragment();
    virtual Fragment *copy() const = 0;
    virtual bool isBlockNamed( const std::string & name ) const;
};


class Text : public Fragment {
public:
    Text( const std::string & text );
    void render( std::ostream & output, const Dictionary & dictionary ) const;
    Fragment *copy() const;
    
private:
    const std::string text;
};


class Property : public Fragment {
public:
    Property( const std::string & name );
    void render( std::ostream & output, const Dictionary & dictionary ) const;
    Fragment *copy() const;
    
private:
    const std::string name;
};

    
}; // namespace Private

    
    
class Block;

//using namespace Private;

    
class Node : public Private::Fragment, public Private::Dictionary {
public:
    ~Node();
    Fragment *copy() const;
    void render( std::ostream & output, const Private::Dictionary & dictionary ) const;
    Block & block( const std::string & name ) const;
    
protected:
    std::vector<Fragment*> fragments;
    
    friend class Template;
};


class Block : public Node {
public:
    Block( const std::string & name );
    Fragment *copy() const;
    ~Block();
    bool isBlockNamed( const std::string & name ) const;
    void enable();
    void disable();
    void repeat( size_t n );
    Node & operator[]( size_t index );
    void render( std::ostream & output, const Dictionary & dictionary ) const;
    
protected:
    const std::string name;
    bool enabled;
    bool resized;
    std::vector<Node*> nodes;
};


class Loader {
public:
    struct Result {
        bool valid;
        std::string data;
        std::string error;
    };
    
    virtual ~Loader();
    virtual Result load( const std::string & name ) = 0;
};


class LoaderFile : public Loader {
public:
    Result load( const std::string & name );
};

    
class LoaderMemory : public Loader {
private:
    std::vector<std::pair<std::string, std::string> > files;
public:
    void add( const std::string & name, const std::string & body );
    Result load( const std::string & name );
};



class Template : public Block {
public:
    Template( Loader & loader );
    void clear();
    void load( const std::string & name );
    void render( std::ostream & output ) const;
    std::string render() const;
    
private:
    Loader & loader;

    void load_recursive( const std::string & name, std::vector<Private::Tokenizer> & files, std::vector<Node*> & nodes );
};



} // namespace Template
    
} // namespace NL

#endif
