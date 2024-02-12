from gensim.models.doc2vec import Doc2Vec, TaggedDocument
from nltk.tokenize import word_tokenize
from numpy import *
from urllib.parse import unquote

import numpy as np


def getVec(text):
    tagged_data = [
        TaggedDocument(words=word_tokenize(_d.lower()), tags=[str(i)])
        for i, _d in enumerate(text)
    ]
    max_epochs = 25
    vec_size = 20
    alpha = 0.025

    model = Doc2Vec(
        vector_size=vec_size, alpha=alpha, min_alpha=0.00025, min_count=1, dm=1
    )
    model.build_vocab(tagged_data)
    print("Building the sample vector model...")
    features = []
    for epoch in range(max_epochs):
        # print('Doc2Vec Iteration {0}'.format(epoch))
        print("*", sep=" ", end="", flush=True)
        model.random.seed(42)
        model.train(tagged_data, total_examples=model.corpus_count,
                    epochs=model.epochs)
        # decrease the learning rate
        model.alpha -= 0.0002
        # fix the learning rate, no decay
        model.min_alpha = model.alpha
    # model.save("d2v.model")
    # print()
    # print("Model Saved")
    for i, line in enumerate(text):
        featureVec = [model.dv[i]]
        lineDecode = unquote(line)
        lineDecode = lineDecode.replace(" ", "")
        lowerStr = str(lineDecode).lower()
        # print("X"+str(i)+"=> "+line)
        # We could expand the features
        # https://websitesetup.org/javascript-cheat-sheet/
        # https://owasp.org/www-community/xss-filter-evasion-cheatsheet
        # https://html5sec.org/

        # add feature for malicious HTML tag count
        feature1 = int(lowerStr.count("<link"))
        feature1 += int(lowerStr.count("<object"))
        feature1 += int(lowerStr.count("<form"))
        feature1 += int(lowerStr.count("<embed"))
        feature1 += int(lowerStr.count("<ilayer"))
        feature1 += int(lowerStr.count("<layer"))
        feature1 += int(lowerStr.count("<style"))
        feature1 += int(lowerStr.count("<applet"))
        feature1 += int(lowerStr.count("<meta"))
        feature1 += int(lowerStr.count("<img"))
        feature1 += int(lowerStr.count("<iframe"))
        feature1 += int(lowerStr.count("<input"))
        feature1 += int(lowerStr.count("<body"))
        feature1 += int(lowerStr.count("<video"))
        feature1 += int(lowerStr.count("<button"))
        feature1 += int(lowerStr.count("<math"))
        feature1 += int(lowerStr.count("<picture"))
        feature1 += int(lowerStr.count("<map"))
        feature1 += int(lowerStr.count("<svg"))
        feature1 += int(lowerStr.count("<div"))
        feature1 += int(lowerStr.count("<a"))
        feature1 += int(lowerStr.count("<details"))
        feature1 += int(lowerStr.count("<frameset"))
        feature1 += int(lowerStr.count("<table"))
        feature1 += int(lowerStr.count("<comment"))
        feature1 += int(lowerStr.count("<base"))
        feature1 += int(lowerStr.count("<image"))
        # add feature for malicious method/event count
        feature2 = int(lowerStr.count("exec"))
        feature2 += int(lowerStr.count("fromcharcode"))
        feature2 += int(lowerStr.count("eval"))
        feature2 += int(lowerStr.count("alert"))
        feature2 += int(lowerStr.count("getelementsbytagname"))
        feature2 += int(lowerStr.count("write"))
        feature2 += int(lowerStr.count("unescape"))
        feature2 += int(lowerStr.count("escape"))
        feature2 += int(lowerStr.count("prompt"))
        feature2 += int(lowerStr.count("onload"))
        feature2 += int(lowerStr.count("onclick"))
        feature2 += int(lowerStr.count("onerror"))
        feature2 += int(lowerStr.count("onpage"))
        feature2 += int(lowerStr.count("confirm"))
        feature2 += int(lowerStr.count("marquee"))
        # add feature for ".js" count
        feature3 = int(lowerStr.count(".js"))
        # add feature for "javascript" count
        feature4 = int(lowerStr.count("javascript"))
        # add feature for length of the string
        feature5 = int(len(lowerStr))
        # add feature for "<script"  count
        feature6 = int(lowerStr.count("<script"))
        feature6 += int(lowerStr.count("&lt;script"))
        feature6 += int(lowerStr.count("%3cscript"))
        feature6 += int(lowerStr.count("%3c%73%63%72%69%70%74"))
        # add feature for special character count
        feature7 = int(lowerStr.count("&"))
        feature7 += int(lowerStr.count("<"))
        feature7 += int(lowerStr.count(">"))
        feature7 += int(lowerStr.count('"'))
        feature7 += int(lowerStr.count("'"))
        feature7 += int(lowerStr.count("/"))
        feature7 += int(lowerStr.count("%"))
        feature7 += int(lowerStr.count("*"))
        feature7 += int(lowerStr.count(";"))
        feature7 += int(lowerStr.count("+"))
        feature7 += int(lowerStr.count("="))
        feature7 += int(lowerStr.count("%3C"))
        # add feature for http count
        feature8 = int(lowerStr.count("http"))

        # append the features
        featureVec = np.append(featureVec, feature1)
        # featureVec = np.append(featureVec,feature2)
        featureVec = np.append(featureVec, feature3)
        featureVec = np.append(featureVec, feature4)
        featureVec = np.append(featureVec, feature5)
        featureVec = np.append(featureVec, feature6)
        featureVec = np.append(featureVec, feature7)
        # featureVec = np.append(featureVec,feature8)
        # print(featureVec)
        features.append(featureVec)
    return features